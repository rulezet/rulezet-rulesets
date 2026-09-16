rule Win_Trojan_Mainman_7
{
strings:
	$a0 = { b997018ae68d960301cd21b43ecd21b43b8d968d }


condition:
	$a0
}