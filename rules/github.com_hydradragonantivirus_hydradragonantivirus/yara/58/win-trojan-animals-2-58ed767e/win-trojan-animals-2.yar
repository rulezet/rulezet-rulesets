rule Win_Trojan_Animals_2
{
strings:
	$a0 = { d10e1400813616002a1981361800734081361a00df37d10e1c00fbf9c7061e00e8e7c7062000ffce813622003b32e9aaf6 }


condition:
	$a0
}