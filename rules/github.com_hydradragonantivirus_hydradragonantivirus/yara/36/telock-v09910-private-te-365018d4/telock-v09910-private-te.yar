import "pe"
rule _tElock_V09910_Private__tE_
{
	meta:
		description = "tElock V0.99-1.0 Private -> tE!"
	strings:
		$0 = {E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}