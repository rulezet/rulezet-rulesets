rule Win_Trojan_Timebomb_2
{
strings:
	$a0 = { 92007a01268c0e9000b0022e81068001e80333d233dbb9640050cd265c720c2e3b16800174 }


condition:
	$a0
}