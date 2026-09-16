rule _ASPack_v1061b_
{
	meta:
		description = "ASPack v1.061b"
	strings:
		$0 = {60 E8 5D 81 ED B8 03 C5 2B 85 0B DE 89 85 17 DE 80 BD 01}
	condition:
		$0 at entrypoint
}