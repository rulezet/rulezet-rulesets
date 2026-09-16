rule Win_Trojan_FrodoSoft_4
{
strings:
	$a0 = { 0500bef709b97003311c46e0fbff55b1358ee9c8245d8e73fffe86eb1353bc0605ba050488b16907f6a15b8c819507 }


condition:
	$a0
}