rule Win_Trojan_Nutcracker_2
{
strings:
	$a0 = { 8b7600ba7519bb7619b8ab1ecd21fa8cd8488ed8803d5a740c803d4d7401c3 }


condition:
	$a0
}