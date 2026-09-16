rule Win_Trojan_SillyC_147
{
strings:
	$a0 = { 4abb0020cd219cb44abbffffcd21b44acd219dc38cd80500108ec0be00018bfeb90c01f3a48ed8b41aba8000cd21580650cbba9201b44e33c9cd217205e80d }


condition:
	$a0
}