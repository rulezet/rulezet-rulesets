rule Win_Trojan_Cholera_2
{
strings:
	$a0 = { fffebafffecd213dfffd74068d8e7103ffd10e1f0e07bf }


condition:
	$a0
}