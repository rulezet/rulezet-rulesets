rule Win_Trojan_Oprobe_4
{
strings:
	$a0 = { b80102b90100ba80008d9e261755bd4523cd135d2680be2617907502eb77b80103b90e00cd }


condition:
	$a0
}