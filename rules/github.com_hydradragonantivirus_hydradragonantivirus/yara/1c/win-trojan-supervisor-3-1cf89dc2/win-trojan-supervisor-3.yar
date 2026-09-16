rule Win_Trojan_Supervisor_3
{
strings:
	$a0 = { 340133c94133d2bbad08cd255b721a2ea0340133c94133d2bbad08cd265b72092ec606330100 }


condition:
	$a0
}