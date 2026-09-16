rule ELCEEF_EICAR_Encrypted_ZIP
{
	meta:
		description = "Detects EICAR file in any encrypted ZIP archive"
		author = "marcin@ulikowski.pl"
		id = "c12d42de-356a-584b-9c48-71e65940f1cf"
		date = "2022-12-13"
		modified = "2022-12-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/rules/EICAR_Encrypted_ZIP.yara#L14-L44"
		license_url = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/LICENSE"
		logic_hash = "56851056671bde38338bd200d9fde59c042f35a2cd84ac9401e716f376c9502c"
		score = 75
		quality = 75
		tags = ""

	strings:
		$local = {
			50 4b 03 04 			?? 00 			?? 00 			?? 00 			?? ?? 			?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			?? ?? ?? ?? 			}

	condition:
		for any i in (1..#local) : (( uint8(@local[i]+6)&0x01 or uint8(@local[i]+6)&0x40) and uint32(@local[i]+14)==0x6851cf3c and uint32(@local[i]+22)==68)
}