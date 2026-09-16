rule Win_Trojan_Unhandled_2
{
strings:
	$a0 = { 03b017cd21b82135cd21891e7d038c067f03ba8002b4 }


condition:
	$a0
}