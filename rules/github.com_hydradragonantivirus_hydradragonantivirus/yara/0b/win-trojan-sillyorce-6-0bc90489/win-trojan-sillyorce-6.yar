rule Win_Trojan_SillyORCE_6
{
strings:
	$a0 = { bfb004b131f3a466b81d004b0066268706840066abc380fc4b750eb8023dcd21930e1fb440b13133d2ea }


condition:
	$a0
}