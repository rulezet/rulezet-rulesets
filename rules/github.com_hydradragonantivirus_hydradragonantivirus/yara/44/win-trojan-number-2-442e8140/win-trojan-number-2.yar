rule Win_Trojan_Number_2
{
strings:
	$a0 = { b8000050bfcc031eb142e8e8feb8015c }


condition:
	$a0
}