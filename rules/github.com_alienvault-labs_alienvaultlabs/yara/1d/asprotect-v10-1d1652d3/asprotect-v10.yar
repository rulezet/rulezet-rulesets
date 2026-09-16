rule _ASProtect_v10_
{
	meta:
		description = "ASProtect v1.0"
	strings:
		$0 = {60 E9 04 E9}
	condition:
		$0 at entrypoint
}