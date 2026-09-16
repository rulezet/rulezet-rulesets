rule Win_Trojan_Rain_1
{
strings:
	$a0 = { 13044848a31304b106d3e08ec0a34e00c7064c001e0050b81c0150b90001fcf3a5cb33c0cdd40e }


condition:
	$a0
}