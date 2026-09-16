rule Win_Trojan_DOS_6
{
strings:
	$a0 = { 1c4147acf2ae756801158bc78bd98bca490802f70e8bf88bcb8b2f46ebe671f001eb04482b46 }


condition:
	$a0
}