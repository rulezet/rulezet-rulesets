rule Win_Trojan_Share_3
{
strings:
	$a0 = { 616e5c61646d696e245d }

	$a1 = { 7061726d31656e63223d6865783a37322c64352c30612c6562 }


condition:
	$a0 and $a1
}