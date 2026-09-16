rule Win_Trojan_SVC_19
{
strings:
	$a0 = { 71112e8c847311c40620002e89846d112e8c846f11 }


condition:
	$a0
}