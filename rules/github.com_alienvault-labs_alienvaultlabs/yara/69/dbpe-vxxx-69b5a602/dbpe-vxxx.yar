rule _DBPE_vxxx_
{
	meta:
		description = "DBPE vx.xx"
	strings:
		$0 = {60 E8 5D 8B FD 81 ED 2B B9 81 EF 83 BD 0F}
	condition:
		$0 at entrypoint
}