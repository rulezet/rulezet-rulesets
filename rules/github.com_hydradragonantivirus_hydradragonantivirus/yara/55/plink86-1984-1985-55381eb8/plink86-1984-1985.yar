import "pe"
rule _PLINK86_1984_1985_
{
	meta:
		description = "PLINK86 1984, 1985"
	strings:
		$0 = {FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26}
	condition:
		$0 at pe.entry_point
}