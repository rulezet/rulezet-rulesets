import "pe"
rule _MoleBox_V23X__MoleStudiocom_
{
	meta:
		description = "MoleBox V2.3X -> MoleStudio.com"
	strings:
		$0 = {E8 00 00 00 00 60 E8 4F 00 00 00}
	condition:
		$0 at pe.entry_point
}