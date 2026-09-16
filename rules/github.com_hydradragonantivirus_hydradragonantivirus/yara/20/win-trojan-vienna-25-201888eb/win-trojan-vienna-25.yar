rule Win_Trojan_Vienna_25
{
strings:
	$a0 = { bd5c00068cc00500108ec089866e0333ff8bf581c60801b9f60281e90801898e6c03f3a407bf0001bee10203f5b9 }


condition:
	$a0
}