rule Win_Trojan_FGT_2
{
strings:
	$a0 = { 8ed8a0feff1f3cfc740a3cfa74063cf87602eb22b4 }


condition:
	$a0
}