rule Win_Trojan_Rage_2
{
strings:
	$a0 = { 8db63301b92f08b41b8a0432c402e132c4c0c402880446e2f0 }


condition:
	$a0
}