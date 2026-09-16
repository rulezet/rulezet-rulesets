import "pe"
rule _WIBUKey_V410A__WIBUSYSTEMS_AG_
{
	meta:
		description = "WIBU-Key V4.10A -> WIBU-SYSTEMS AG"
	strings:
		$0 = {F7 05 ?? ?? ?? ?? FF 00 00 00 75 12}
	condition:
		$0 at pe.entry_point
}