rule Win_Trojan_C_314
{
strings:
	$a0 = { 4175746f53746172742d44726f707065722e657865 }

	$a1 = { 5370616d4665726b656c }


condition:
	$a0 and $a1
}