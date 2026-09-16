rule Win_Trojan_QFat_5
{
strings:
	$a0 = { 2193b440b92600baf502cd21b43ecd21e97efeb002b9ff0033d2cd26b003b9ff0033d2cd26b004 }


condition:
	$a0
}