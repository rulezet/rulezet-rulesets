rule RisePro_stealer : hardened
{
	meta:
		version = "1.0"
		malware = "RisePro"
		description = "RisePro Stealer detection base on deobfuscation routine repetition"
		source = "SEKOIA.IO"
		classification = "TLP:GREEN"
		ruleset = "994256c7d4affb121a5c4b28414789de95e141fd.yar"
		repository = "LeakIX/yara-repo-otx"
		source_url = "https://github.com/LeakIX/yara-repo-otx/blob/211ad0b9355b0b1aafc850494449a2603f012a07/994256c7d4affb121a5c4b28414789de95e141fd.yar"
		score = 75

	strings:
		$pxor = {66 0f ef 85}
		$mov_dword_ptr1 = {c7 85}
		$mov_dword_ptr2 = {c7 45}

	condition:
		uint16be( 0 ) == 0x4d5a and #mov_dword_ptr1 > 5000 and #mov_dword_ptr2 > 800 and #pxor > 1000
}