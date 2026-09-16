rule Win_Trojan_DM_11
{
strings:
	$a0 = { 018bde80379043e2fac3bedd02bf000157a5a533c08e }


condition:
	$a0
}