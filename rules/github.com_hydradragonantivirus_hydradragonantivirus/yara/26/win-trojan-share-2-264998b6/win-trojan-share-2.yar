rule Win_Trojan_Share_2
{
strings:
	$a0 = { 616e5c61646d696e245d }

	$a1 = { 7061726d31656e63223d6865783a36352c63382c30322c6538 }

	$a2 = { 72656d61726b223d2222 }


condition:
	$a0 and $a1 and $a2
}