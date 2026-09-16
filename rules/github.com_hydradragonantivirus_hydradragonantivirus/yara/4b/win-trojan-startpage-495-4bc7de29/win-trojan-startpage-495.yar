rule Win_Trojan_Startpage_495
{
strings:
	$a0 = { 558bec83c4ec535633c08945ecb86857 }

	$a1 = { 4175746f72756e }

	$a2 = { 72537461727450616765 }

	$a3 = { 416e74692d426c6178782c }


condition:
	$a0 and $a1 and $a2 and $a3
}