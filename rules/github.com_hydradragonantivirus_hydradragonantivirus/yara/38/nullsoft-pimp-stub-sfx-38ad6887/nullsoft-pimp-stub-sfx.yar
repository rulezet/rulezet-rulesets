import "pe"
rule _Nullsoft_PiMP_Stub__SFX_
{
	meta:
		description = "Nullsoft PiMP Stub -> SFX"
	strings:
		$0 = {81 EC ?? ?? ?? ?? 53 55 56}
	condition:
		$0 at pe.entry_point
}