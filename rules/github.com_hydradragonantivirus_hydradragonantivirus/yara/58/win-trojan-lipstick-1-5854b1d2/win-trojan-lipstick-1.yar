rule Win_Trojan_Lipstick_1
{
strings:
	$a0 = { de2a34b8ff70100e2d0b46e864fe8850278027ebd747034706142a022e2e4883ec2cbfaa1c }


condition:
	$a0
}