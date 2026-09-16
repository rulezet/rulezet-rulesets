rule Win_Trojan_SU_1
{
strings:
	$a0 = { 83c501eb03bd98fe8bf2e85d0083c703892db4408bfa2bd1b98301cd217303eb1d903d830175 }


condition:
	$a0
}