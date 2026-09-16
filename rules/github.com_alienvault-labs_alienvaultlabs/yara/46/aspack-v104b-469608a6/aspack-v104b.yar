rule _ASPack_v104b_
{
	meta:
		description = "ASPack v1.04b"
	strings:
		$0 = {75 ??}
	condition:
		$0 at entrypoint
}