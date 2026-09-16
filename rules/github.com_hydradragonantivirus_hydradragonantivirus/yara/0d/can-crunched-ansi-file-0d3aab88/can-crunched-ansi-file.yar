import "pe"
rule _CAN_Crunched_ANsi_file_
{
	meta:
		description = "CAN (Crunched ANsi) file"
	strings:
		$0 = {CA 01}
	condition:
		$0 at pe.entry_point
}