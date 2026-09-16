import "pe"
rule _Petite_v22_Compresor__wwwun4seencompetite_
{
	meta:
		description = "Petite v2.2 (Compresor) -> www.un4seen.com/petite/"
	strings:
		$0 = {B8 00 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}