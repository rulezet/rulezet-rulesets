import "pe"
rule _UPX_v103__v104_
{
	meta:
		description = "UPX v1.03 - v1.04"
	strings:
		$0 = {60 BE 8D BE C7 87 57 83 CD FF EB 0E 8A 06 46 88 07 47 01 DB 75 07}
	condition:
		$0 at pe.entry_point
}