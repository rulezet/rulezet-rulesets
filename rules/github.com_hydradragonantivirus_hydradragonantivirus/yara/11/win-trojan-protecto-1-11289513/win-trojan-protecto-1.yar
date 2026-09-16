rule Win_Trojan_Protecto_1
{
strings:
	$a0 = { 8bd683c24ab8003dcd217303eb39908b }


condition:
	$a0
}