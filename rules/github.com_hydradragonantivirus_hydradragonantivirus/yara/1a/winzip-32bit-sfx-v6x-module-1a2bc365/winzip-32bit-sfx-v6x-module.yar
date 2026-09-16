import "pe"
rule _WinZip_32bit_SFX_v6x_module_
{
	meta:
		description = "WinZip 32-bit SFX v6.x module"
	strings:
		$0 = {53 FF 15 ?? B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 FF}
	condition:
		$0 at pe.entry_point
}