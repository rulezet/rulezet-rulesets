rule Win_Trojan_Dead_12
{
strings:
	$a0 = { e800005d83ed038db6????bf0001b90500f3a4b8addecd213d01237508 }


condition:
	$a0
}