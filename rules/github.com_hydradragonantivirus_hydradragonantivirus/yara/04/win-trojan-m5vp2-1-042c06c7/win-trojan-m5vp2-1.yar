rule Win_Trojan_M5VP2_1
{
strings:
	$a0 = { 0103360301b97d06b0ff300446e2fb41a3ff03465cff404ff8fcc1fcfe0c5b4bd532de7e0636f889fc16a9fd4bd5 }


condition:
	$a0
}