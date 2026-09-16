rule Win_Trojan_Mud_1
{
strings:
	$a0 = { 2e424154032e4d45042e44495a07444952494e464fc8000100bf02070e576a20bf52001e579a }


condition:
	$a0
}