rule Win_Trojan_Wanderer_6
{
strings:
	$a0 = { 52b440b9900133d2e83000b000e82500b440b90500ba8e00e82000b801575a59 }


condition:
	$a0
}