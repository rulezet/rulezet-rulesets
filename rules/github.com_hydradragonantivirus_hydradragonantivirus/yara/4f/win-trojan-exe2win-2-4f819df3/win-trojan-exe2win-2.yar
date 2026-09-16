rule Win_Trojan_Exe2Win_2
{
strings:
	$a0 = { cd2193b440b9c602ba0001cd21b43ecd21b44fcd21 }


condition:
	$a0
}