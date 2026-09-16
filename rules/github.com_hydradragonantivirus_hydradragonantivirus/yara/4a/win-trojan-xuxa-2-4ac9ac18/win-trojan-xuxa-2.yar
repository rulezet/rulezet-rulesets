rule Win_Trojan_Xuxa_2
{
strings:
	$a0 = { 4e01b40bcd21b9c7032e8a9617018a0432c2eb0590b44ccd21c0c00526880546474975e5eb01 }


condition:
	$a0
}