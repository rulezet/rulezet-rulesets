rule Win_Trojan_Peed_131
{
strings:
	$a0 = { 60e8 }

	$a1 = { bda46deffe6a046a03 }


condition:
	$a0 and $a1
}