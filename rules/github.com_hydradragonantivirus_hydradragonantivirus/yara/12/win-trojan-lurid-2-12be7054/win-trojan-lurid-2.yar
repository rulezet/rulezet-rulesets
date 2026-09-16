rule Win_Trojan_Lurid_2
{
strings:
	$a0 = { dd032bca8db53f018d953f018d9d3e018a27578bfaac2ac4f6d032c402c4aae2f45fe9fb00cc }


condition:
	$a0
}