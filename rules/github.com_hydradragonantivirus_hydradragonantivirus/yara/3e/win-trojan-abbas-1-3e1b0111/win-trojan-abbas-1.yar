rule Win_Trojan_Abbas_1
{
strings:
	$a0 = { 050547e2fab94c04ba0000e83800bfeb01b9a0009c802d }


condition:
	$a0
}