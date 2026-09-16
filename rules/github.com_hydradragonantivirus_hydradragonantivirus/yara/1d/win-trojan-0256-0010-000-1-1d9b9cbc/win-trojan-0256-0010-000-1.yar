rule Win_Trojan__0256_0010_000_1
{
strings:
	$a0 = { 19062ea31b06e8bc01b440ba1706b91800cd21eb45e8ad01b43fba2f06b90500cd212e813e3206 }


condition:
	$a0
}