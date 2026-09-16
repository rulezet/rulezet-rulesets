rule Win_Trojan_AntiFort_2
{
strings:
	$a0 = { b476b2d47fde8ed4c7f23235babb8576e69a39167fc6b90dc6e2bcc90d73b57475cd0bceb17eb220 }


condition:
	$a0
}