import "pe"
rule _HQR_data_file_
{
	meta:
		description = "HQR data file"
	strings:
		$0 = {48 00 00 00 ?? 02 00 00 ?? ?? 00 00 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}