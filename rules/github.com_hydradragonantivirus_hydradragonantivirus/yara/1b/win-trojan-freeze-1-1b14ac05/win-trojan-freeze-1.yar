rule Win_Trojan_Freeze_1
{
strings:
	$a0 = { 5a45b8efefcd213dfefeb8000074 }


condition:
	$a0
}