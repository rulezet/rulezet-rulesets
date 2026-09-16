rule Win_Trojan_K4_1
{
strings:
	$a0 = { 84a502899ca902b803258bd681c20602cd21837c4e0074328bde83c3578bfe81c7ad028b4c4ec7 }


condition:
	$a0
}