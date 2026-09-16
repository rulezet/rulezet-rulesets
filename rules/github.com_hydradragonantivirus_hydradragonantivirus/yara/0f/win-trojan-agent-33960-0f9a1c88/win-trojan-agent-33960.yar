rule Win_Trojan_Agent_33960
{
strings:
	$a0 = { 89ee89ee8bf346bf6410400081f6e6048401 }


condition:
	$a0
}