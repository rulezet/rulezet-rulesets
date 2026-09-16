rule Win_Trojan_HH_1
{
strings:
	$a0 = { fc30742d3d003d74283d004b74232eff2e3200b42acd21 }


condition:
	$a0
}