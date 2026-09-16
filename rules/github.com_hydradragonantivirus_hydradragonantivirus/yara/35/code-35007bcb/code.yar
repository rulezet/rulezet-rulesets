import "pe"
rule _code_
{
	meta:
		description = "code"
	strings:
		$0 = {83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00}
	condition:
		$0 at pe.entry_point
}