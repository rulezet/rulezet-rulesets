rule Win_Trojan_W_316
{
strings:
	$a0 = { 3d9090909003ca8b4154fe41558d3c028741282b41287e26909090906a29 }


condition:
	$a0
}