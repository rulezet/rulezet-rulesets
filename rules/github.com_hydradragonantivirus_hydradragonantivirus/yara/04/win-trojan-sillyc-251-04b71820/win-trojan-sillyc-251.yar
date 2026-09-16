rule Win_Trojan_SillyC_251
{
strings:
	$a0 = { b44eb1238d96cf01cd217303e99700ba9e0033c9e88600b8023dcd21 }


condition:
	$a0
}