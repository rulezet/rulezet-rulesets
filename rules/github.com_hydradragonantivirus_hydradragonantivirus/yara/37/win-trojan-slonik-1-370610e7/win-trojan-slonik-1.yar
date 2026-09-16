rule Win_Trojan_Slonik_1
{
strings:
	$a0 = { 2818ed84c9c90c23c04eaffd80f52e0e00402e02a23cf5e5f6e0071ad82dce28450c3b5b810d }


condition:
	$a0
}