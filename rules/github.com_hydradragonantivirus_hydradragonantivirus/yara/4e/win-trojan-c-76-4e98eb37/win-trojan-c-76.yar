rule Win_Trojan_C_76
{
strings:
	$a0 = { c406eb2ab81e0350e82afe590bc07516833e1c03007c0f7f08813e1a032c197605b81e03eb19b8 }


condition:
	$a0
}