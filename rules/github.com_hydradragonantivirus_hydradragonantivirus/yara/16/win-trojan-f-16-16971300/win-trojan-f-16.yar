rule Win_Trojan_F_16
{
strings:
	$a0 = { 830040482e8a242e32264f00424a2e882446434b81fe640475ea5840485ec3 }


condition:
	$a0
}