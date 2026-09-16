rule Win_Trojan_Intruder_5
{
strings:
	$a0 = { 32c0aab0010ac0c35f32c0c3ba0600b41acd21bfaf00be }


condition:
	$a0
}