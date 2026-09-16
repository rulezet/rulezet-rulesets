rule _PE_Spin_v04x_
{
	meta:
		description = "PE Spin v0.4x"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B}
	condition:
		$0
}