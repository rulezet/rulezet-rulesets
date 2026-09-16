import "pe"
rule _E2C_by_DoP_
{
	meta:
		description = "E2C by DoP"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3}
	condition:
		$0 at pe.entry_point
}