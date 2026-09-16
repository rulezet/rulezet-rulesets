import "pe"
rule _PROTECT_EXECOM_v50_
{
	meta:
		description = "PROTECT! EXE/COM v5.0"
	strings:
		$0 = {1E 0E 0E 1F 07}
	condition:
		$0 at pe.entry_point
}