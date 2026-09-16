rule Win_Trojan_B_56
{
strings:
	$a0 = { 7cfba113042d0600a31304b106d3e08ec0b80b02b90200ba8000cd13bb7c010653cb }


condition:
	$a0
}