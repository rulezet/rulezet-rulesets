rule Win_Trojan_Bancos_899
{
strings:
	$a0 = { 8aedd1a36e09bef70981c7549c7ad0afaa1d2280d74fb6832d3ff5fa91de143f23c79bb8c2bb4d504d22beee352631ded03fdfc3d3d50f68303f7527698ac1ed }


condition:
	$a0
}