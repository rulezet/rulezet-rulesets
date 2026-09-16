rule Win_Trojan_TPVO_1
{
strings:
	$a0 = { 8ed3bc007c8ec4b80802b9ca33ba8000cd1372feeade01007c }


condition:
	$a0
}