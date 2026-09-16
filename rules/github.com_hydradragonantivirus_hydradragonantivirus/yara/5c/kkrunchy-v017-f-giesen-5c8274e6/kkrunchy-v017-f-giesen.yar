rule _kkrunchy_v017__F_Giesen_
{
	meta:
		description = "kkrunchy v0.17 -> F. Giesen"
	strings:
		$0 = {FC FF 4D 08 31 D2 8D 7D 30 BE}
	condition:
		$0
}