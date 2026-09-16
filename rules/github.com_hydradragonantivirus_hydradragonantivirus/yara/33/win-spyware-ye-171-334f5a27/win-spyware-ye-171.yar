rule Win_Spyware_ye_171
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a876b207c3e295c7e99639a3c3e090 }


condition:
	$a0
}