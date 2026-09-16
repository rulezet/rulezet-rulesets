rule Win_Trojan_Rubb_1
{
strings:
	$a0 = { 1e91035951a1ad0303c8ba0010b4409cff1e910358b43e9cff1e9103e86eff33c0 }


condition:
	$a0
}