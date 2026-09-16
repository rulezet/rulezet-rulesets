import "pe"
rule _EXECryptor_13045__SoftComplete_Development_
{
	meta:
		description = "EXECryptor 1.3.0.45 -> SoftComplete Development"
	strings:
		$0 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 31 C0 89 41 14 89 41 18 80 A1}
	condition:
		$0 at pe.entry_point
}