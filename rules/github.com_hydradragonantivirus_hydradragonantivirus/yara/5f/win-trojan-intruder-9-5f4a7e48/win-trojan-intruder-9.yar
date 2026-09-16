rule Win_Trojan_Intruder_9
{
strings:
	$a0 = { c0aab0010ac0c35f32c0c3ba2104b41acd21bfca04be }


condition:
	$a0
}