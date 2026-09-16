rule Win_Trojan_Rose_1
{
strings:
	$a0 = { 1fa189023b0689007416e80701b8010331dbb90100cd13eb078b4c028b14cd13ea007c0000 }


condition:
	$a0
}