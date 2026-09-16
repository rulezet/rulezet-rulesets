import "pe"
rule _EXE_Stealth_v27_
{
	meta:
		description = "EXE Stealth v2.7"
	strings:
		$0 = {EB ?? 60 EB ?? E8 ?? ?? ?? ?? 5D 81 ED B0 27}
	condition:
		$0 at pe.entry_point
}