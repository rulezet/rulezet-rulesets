rule Win_Trojan_Onlinegames_18
{
strings:
	$a0 = { 558bec538b5d08568b750c57 }

	$a1 = { 2f6d616e6167652f6d6a323030392f6765742e617370 }

	$a2 = { 6d79636f646531393833 }


condition:
	$a0 and $a1 and $a2
}