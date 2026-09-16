rule Win_Trojan_Microbes_1
{
strings:
	$a0 = { 042d0400a31304b106d3e08ec006c706 }


condition:
	$a0
}