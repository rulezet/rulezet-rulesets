rule Win_Trojan_Anthrax_1
{
strings:
	$a0 = { 832e130402cd12b106d3e08ec0bf }


condition:
	$a0
}