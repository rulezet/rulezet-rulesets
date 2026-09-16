rule Win_Trojan_Zapchast_131
{
strings:
	$a0 = { 7773687368656c6c2e72756e2261646d2e626174 }


condition:
	$a0
}