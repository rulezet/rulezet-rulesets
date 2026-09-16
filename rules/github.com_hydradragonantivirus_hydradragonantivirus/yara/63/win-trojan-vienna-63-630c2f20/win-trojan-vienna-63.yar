rule Win_Trojan_Vienna_63
{
strings:
	$a0 = { 84280081c115038bfe81ef1302890db440b9b9028bd681ea1502cd21721f3db902751ab80042b9 }


condition:
	$a0
}