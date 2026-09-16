rule Win_Trojan_Chloride_1
{
strings:
	$a0 = { 0802a3bc01fc33f6bf2002b1f0f3a5c747147601908367160090c74708020090b801035951cd13 }


condition:
	$a0
}