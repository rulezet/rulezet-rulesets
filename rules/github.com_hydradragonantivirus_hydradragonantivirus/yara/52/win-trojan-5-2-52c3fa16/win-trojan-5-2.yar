rule Win_Trojan_5_2
{
strings:
	$a0 = { 8ed8a16c041fe80500b8004ccd21fc33d20e1fb99000f7f1e87b00a21500e87500a21e0092b206f6f2befd01bb }


condition:
	$a0
}