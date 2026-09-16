rule Win_Trojan_Mirea_2
{
strings:
	$a0 = { c54be132694a43c5325f4a43d132554a43f7345b1b5b4b34 }


condition:
	$a0
}