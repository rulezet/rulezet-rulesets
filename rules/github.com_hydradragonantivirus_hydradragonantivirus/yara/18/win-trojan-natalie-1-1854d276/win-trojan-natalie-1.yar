rule Win_Trojan_Natalie_1
{
strings:
	$a0 = { cd21723c488ec026c70601000800408ec02e8b0ec50280e903b80302ba800033dbcd13 }


condition:
	$a0
}