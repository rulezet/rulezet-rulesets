rule Win_Trojan_UX_2
{
strings:
	$a0 = { bc005589e5b800019adf04bc0081ec0001b8201c509a3f02bc00a3fa018916fc01b80020509a3f02bc00a3fe01 }


condition:
	$a0
}