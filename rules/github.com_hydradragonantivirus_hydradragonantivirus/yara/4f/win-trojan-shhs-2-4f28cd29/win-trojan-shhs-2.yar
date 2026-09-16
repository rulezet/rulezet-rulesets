rule Win_Trojan_SHHS_2
{
strings:
	$a0 = { bb3e01a006010ac0740b30074302c781fb49037ef5c3 }


condition:
	$a0
}