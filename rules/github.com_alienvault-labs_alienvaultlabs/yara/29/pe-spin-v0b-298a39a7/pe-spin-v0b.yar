rule _PE_Spin_v0b_
{
	meta:
		description = "PE Spin v0.b"
	strings:
		$0 = {66 9C 60 E8 CA 03 04 05 06 07}
	condition:
		$0 at entrypoint
}