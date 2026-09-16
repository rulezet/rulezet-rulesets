rule Win_Trojan_Timebomb_1
{
strings:
	$a0 = { 9000b0022e81068201e80333d233dbb9640050cd265c720c2e3b168201740583c264ebef58 }


condition:
	$a0
}