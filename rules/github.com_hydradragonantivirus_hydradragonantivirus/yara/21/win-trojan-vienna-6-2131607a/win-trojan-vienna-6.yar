rule Win_Trojan_Vienna_6
{
strings:
	$a0 = { 2f038bfe81ef2d02890db440b91f048bd681ea2f02cd2172 }


condition:
	$a0
}