rule Win_Trojan_Simplex_1
{
strings:
	$a0 = { b9f801b440cd21e8a900582d0400a3f201baf001b90400b440cd215a59b80157cd215958cd21 }


condition:
	$a0
}