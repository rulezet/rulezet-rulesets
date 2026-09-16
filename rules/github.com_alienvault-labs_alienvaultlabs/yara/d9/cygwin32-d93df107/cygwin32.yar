rule _Cygwin32_
{
	meta:
		description = "Cygwin32"
	strings:
		$0 = {6A FF 15}
	condition:
		$0 at entrypoint
}