rule Win_Trojan_DKME_1
{
strings:
	$a0 = { 6face6a471a39cdde99de3e3cb77e33e9723b004f10216ac16b59be325b00497239ce7e39de5e3b0 }


condition:
	$a0
}