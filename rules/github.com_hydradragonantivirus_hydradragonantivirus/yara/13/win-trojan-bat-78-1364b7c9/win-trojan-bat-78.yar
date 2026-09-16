rule Win_Trojan_BAT_78
{
strings:
	$a0 = { 72656e20633a5c72656379636c65645c2a2e626174202a2e626174 }

	$a1 = { 64656c74726565202f79206d736e }


condition:
	$a0 and $a1
}