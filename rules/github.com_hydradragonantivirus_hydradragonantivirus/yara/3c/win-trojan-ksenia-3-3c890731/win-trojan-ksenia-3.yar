rule Win_Trojan_Ksenia_3
{
strings:
	$a0 = { 329de83210b430cd218bec8b6efa81ed0b021e6aff1fbe0700ba2e0032141f8db63812b90510 }


condition:
	$a0
}