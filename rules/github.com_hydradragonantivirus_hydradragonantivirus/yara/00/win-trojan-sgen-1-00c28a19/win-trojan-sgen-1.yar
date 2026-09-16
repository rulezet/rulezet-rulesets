rule Win_Trojan_SGEN_1
{
strings:
	$a0 = { 16460f8b03fceb4590cd138b01b40081e1f0048b037510b83a0bb99d01f2ae8b018a043c51 }


condition:
	$a0
}