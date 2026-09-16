rule Win_Trojan_VGEN_421
{
strings:
	$a0 = { 0133e4b98b00ad86c450e2faffe4cd2090909090909090909090909090909090e4fffae250e086ad008bb9e43100 }


condition:
	$a0
}