import "pe"
rule _MSLRHv031__xuecao_
{
	meta:
		description = "MSLRHv0.31 -> xuecao"
	strings:
		$0 = {60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1}
	condition:
		$0 at pe.entry_point
}