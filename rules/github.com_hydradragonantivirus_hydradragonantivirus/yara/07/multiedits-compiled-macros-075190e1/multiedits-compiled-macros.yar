import "pe"
rule _MultiEdits_compiled_macros_
{
	meta:
		description = "MultiEdit`s compiled macros"
	strings:
		$0 = {1E AA}
	condition:
		$0 at pe.entry_point
}