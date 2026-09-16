rule Win_Trojan_Stinkfoot_6
{
strings:
	$a0 = { 1e7801b440b9e303c606730100cd21 }


condition:
	$a0
}