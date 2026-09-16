rule Win_Trojan_Friends_1
{
strings:
	$a0 = { b9510503cbb4408b5d57cd7ab80157 }


condition:
	$a0
}