import "pe"
rule _Microsoft_C_for_Windows_
{
	meta:
		description = "Microsoft C for Windows"
	strings:
		$0 = {33 ED 55 9A ?? ?? ?? ?? 0B C0 74}
	condition:
		$0 at pe.entry_point
}