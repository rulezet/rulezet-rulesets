rule Win_Trojan_Alfa_1
{
strings:
	$a0 = { 7c8ed8a113042d0300a31304b106d3e08ec0be007cbf0000b90001f3a506b8a40050cb0e1f80 }


condition:
	$a0
}