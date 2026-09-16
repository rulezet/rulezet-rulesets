rule Win_Trojan_Hupigon_1716
{
strings:
	$a0 = { 90e8000000005883c00b50ff250c204000 }

	$a1 = { 5068656c3332686b }


condition:
	$a0 and $a1
}