rule Win_Trojan_B_98
{
strings:
	$a0 = { 03b90700bb0002ba8000cd138a16040052bfbe01bebe03b94201c606040080 }


condition:
	$a0
}