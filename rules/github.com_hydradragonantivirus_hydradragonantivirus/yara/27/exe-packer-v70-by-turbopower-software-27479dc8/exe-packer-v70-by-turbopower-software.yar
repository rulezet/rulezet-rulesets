import "pe"
rule _EXE_Packer_v70_by_TurboPower_Software_
{
	meta:
		description = "EXE Packer v7.0 by TurboPower Software"
	strings:
		$0 = {1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE}
	condition:
		$0 at pe.entry_point
}