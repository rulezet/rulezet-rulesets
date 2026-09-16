rule Win_Trojan_Pottie_1
{
strings:
	$a0 = { b440b9f6008d960401cd21e80100c38b861c018db64201b95c0031044646e2fac3 }


condition:
	$a0
}