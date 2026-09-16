import "pe"
rule _PROTECT_EXECOM_v60_
{
	meta:
		description = "PROTECT! EXE/COM v6.0"
	strings:
		$0 = {1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8}
	condition:
		$0 at pe.entry_point
}