rule Win_Trojan_LX_2
{
strings:
	$a0 = { 0ee800005e83eeec8bfeb9b207fcac32c10401aae2f8eb00 }


condition:
	$a0
}