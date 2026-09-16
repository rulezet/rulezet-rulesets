import "pe"
rule _May_be_Pklite_Header_Version_v6v2_extra__0__v5_
{
	meta:
		description = "May be Pklite Header Version %v6.^%v2 [extra > 0 - %v5"
	strings:
		$0 = {50 6B}
		$1 = {50 4B}
	condition:
		$0 or $1 at pe.entry_point
}