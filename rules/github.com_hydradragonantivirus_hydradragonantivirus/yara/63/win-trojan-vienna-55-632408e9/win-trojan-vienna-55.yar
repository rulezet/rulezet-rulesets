rule Win_Trojan_Vienna_55
{
strings:
	$a0 = { b988028bd681eaf901cd21721f3d }


condition:
	$a0
}