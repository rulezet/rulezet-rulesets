rule Win_Trojan_Philis_140
{
strings:
	$a0 = { 538134249144d36a5b53bb4468 }


condition:
	$a0
}