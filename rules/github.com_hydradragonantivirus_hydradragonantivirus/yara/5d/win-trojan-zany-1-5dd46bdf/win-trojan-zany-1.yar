rule Win_Trojan_Zany_1
{
strings:
	$a0 = { ed08018db67801bf000157a5a5b44e33c98d967201cd21724eb8023dba9e00cd2193b43fb904008d967801cd213e }


condition:
	$a0
}