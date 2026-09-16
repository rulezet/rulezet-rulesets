import "pe"
rule _PKZIP_Archive_
{
	meta:
		description = "PKZIP Archive"
	strings:
		$0 = {50 4B 03 04}
	condition:
		$0 at pe.entry_point
}