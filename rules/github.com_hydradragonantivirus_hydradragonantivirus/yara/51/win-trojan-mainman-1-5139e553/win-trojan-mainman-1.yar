rule Win_Trojan_Mainman_1
{
strings:
	$a0 = { b9c8008ae68d960301cd21b43ecd21b43b8d96be01cd }


condition:
	$a0
}