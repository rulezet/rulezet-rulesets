rule Win_Trojan_Ultimate_3
{
strings:
	$a0 = { b44e33c98d96????cd217207e80500b44febf5c3b801438d96????33c9cd21b8023dcd2172ed93b43fb914008d96????cd21 }


condition:
	$a0
}