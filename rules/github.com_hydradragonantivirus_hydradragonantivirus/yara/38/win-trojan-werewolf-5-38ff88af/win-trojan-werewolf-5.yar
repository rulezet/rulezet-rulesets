rule Win_Trojan_WereWolf_5
{
strings:
	$a0 = { 940272f4c3e8edffc6069802b8cd21c606980281eb }


condition:
	$a0
}