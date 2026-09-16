rule Win_Trojan_LoveMe_2
{
strings:
	$a0 = { e2b9345eba2e80be4000bf02be505351525657b8b9e4bbe660b9b0f550535189260400cd01 }


condition:
	$a0
}