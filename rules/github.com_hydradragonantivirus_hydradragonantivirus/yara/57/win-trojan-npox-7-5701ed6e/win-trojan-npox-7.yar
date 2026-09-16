rule Win_Trojan_NPox_7
{
strings:
	$a0 = { 7b75080e1fba6204eb0690e85e017272b80043cd2172 }


condition:
	$a0
}