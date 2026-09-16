rule _Possibly_PCX_graphics_format_
{
	meta:
		description = "Possibly PCX graphics format"
	strings:
		$0 = {10 ?? 01}
		$1 = {0A ?? 01}
	condition:
		$0 at entrypoint or $1
}