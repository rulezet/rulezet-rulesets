import "pe"
rule _tElock_099__10_private__tE_
{
	meta:
		description = "tElock 0.99 - 1.0 private -> tE!"
	strings:
		$0 = {E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}