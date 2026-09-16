rule Win_Trojan_TPVO_4
{
strings:
	$a0 = { db8ed3bc007c8ec4b80802b90150ba0000cd1372feeadc01007c }


condition:
	$a0
}