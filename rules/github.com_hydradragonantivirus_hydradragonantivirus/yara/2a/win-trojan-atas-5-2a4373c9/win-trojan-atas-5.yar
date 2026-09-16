rule Win_Trojan_Atas_5
{
strings:
	$a0 = { 0201b0beb97c0cbe130001fe300446e2fb }


condition:
	$a0
}