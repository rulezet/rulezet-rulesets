rule Win_Trojan_Trigger_1
{
strings:
	$a0 = { 5db8f00cbb4144cd2181fb4847753c1e060e1f33c08d76008ec033ffb90800f3a77408403d00a072eceb1b89464f8e }


condition:
	$a0
}