rule Win_Trojan_Datalock_3
{
strings:
	$a0 = { a12c00508cd8488ed8812e030080 }


condition:
	$a0
}