rule Win_Trojan_Gen_247
{
strings:
	$a0 = { 9a0000aa005589e583ec029a010caa00c606a21900e80efca04e0030e4d1e08846ffb0003a46ff7f1da23c1aeb04fe06 }


condition:
	$a0
}