rule Win_Trojan_Yesmile_1
{
strings:
	$a0 = { db8edb8ed3bc007cfba113042d0500a31304b106d3e08ec0b80902b90200ba8000cd13bb7c01 }


condition:
	$a0
}