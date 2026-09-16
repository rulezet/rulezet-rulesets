rule _MinGW_GCC_v2x_
{
	meta:
		description = "MinGW GCC v2.x"
	strings:
		$0 = {55 89 E5 FF}
		$1 = {55 89 E5 E8 C9 C3 45 58}
		$2 = {55 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}