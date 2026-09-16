rule _Microsoft_Visual_Cpp_
{
	meta:
		description = "Microsoft Visual C++"
	strings:
		$0 = {8B 44 24 08 83}
		$1 = {53 56 57 BB 8B 55 3B FB}
		$2 = {FF FF FF ?? ?? ?? ?? ?? ?? 30 ?? ?? ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}