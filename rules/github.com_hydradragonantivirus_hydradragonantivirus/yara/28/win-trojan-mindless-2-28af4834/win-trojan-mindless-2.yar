rule Win_Trojan_Mindless_2
{
strings:
	$a0 = { 013dba9e00cd218bd8b457b000cd215152ba0001b9ad01b440cd215a59b457b001cd21 }


condition:
	$a0
}