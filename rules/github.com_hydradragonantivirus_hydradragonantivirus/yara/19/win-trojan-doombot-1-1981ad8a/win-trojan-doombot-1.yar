rule Win_Trojan_Doombot_1
{
strings:
	$a0 = { 558bec83c4f05356b8e83f0010e87af6ffffbe6866001033c05568db40001064ff30648920e8faf8ffffbaec4000108bc6e8f2faffff }


condition:
	$a0
}