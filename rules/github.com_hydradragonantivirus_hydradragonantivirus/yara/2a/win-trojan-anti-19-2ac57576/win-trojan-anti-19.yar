rule Win_Trojan_Anti_19
{
strings:
	$a0 = { d1e080e40380c4028ac48bd832ff }


condition:
	$a0
}