rule Win_Trojan_Funky_1
{
strings:
	$a0 = { fa2d7df4f2324563fd1c5d3afc03f874bad0060135b92d8afc7014da0234e3b92db93386bcda21cc }


condition:
	$a0
}