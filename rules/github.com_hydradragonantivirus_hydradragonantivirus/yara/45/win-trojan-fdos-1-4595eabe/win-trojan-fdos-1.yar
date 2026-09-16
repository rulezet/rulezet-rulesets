rule Win_Trojan_FDoS_1
{
strings:
	$a0 = { cb1e7cfee157026e59a284e25d35513fa2ca7babf550554b52554bd1185906aeec9c7adc9dc8649f6065 }


condition:
	$a0
}