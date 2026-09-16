rule Win_Trojan_Markus_3
{
strings:
	$a0 = { 33db8ed3bc007cfb36832e13040690cd12b106d3e08ec006b8ab0250b80c02b90300ba8000cd13 }


condition:
	$a0
}