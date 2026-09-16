rule Win_Trojan_Sirius_22
{
strings:
	$a0 = { 70841faebca4d4c4d6a79ff1c7e5e67c738b27354e294fbc26a82010ffa2aacfe67bfdc733ae3c7b }


condition:
	$a0
}