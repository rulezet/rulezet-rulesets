import "pe"
rule _AcidCrypt__AciDLeo_
{
	meta:
		description = "AcidCrypt -> AciDLeo"
	strings:
		$0 = {60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB}
	condition:
		$0 at pe.entry_point
}