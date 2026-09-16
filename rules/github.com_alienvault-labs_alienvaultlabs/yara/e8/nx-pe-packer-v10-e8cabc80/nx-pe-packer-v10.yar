rule _NX_PE_Packer_v10_
{
	meta:
		description = "NX PE Packer v1.0"
	strings:
		$0 = {EB 02 E8 E7}
	condition:
		$0 at entrypoint
}