import "pe"
rule _HP48sx_graphics_format_
{
	meta:
		description = "HP-48sx graphics format"
	strings:
		$0 = {48 50 48 50 34 38 2D 41}
	condition:
		$0 at pe.entry_point
}