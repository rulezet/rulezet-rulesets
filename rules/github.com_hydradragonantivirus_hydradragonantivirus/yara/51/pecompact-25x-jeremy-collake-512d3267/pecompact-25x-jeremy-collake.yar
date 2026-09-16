import "pe"
rule _PECompact_25x__Jeremy_Collake_
{
	meta:
		description = "PECompact 2.5x -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? ?? FF E0}
	condition:
		$0 at pe.entry_point
}