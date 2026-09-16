rule Win_Trojan_SillyC_219
{
strings:
	$a0 = { 8bd7cd213bc17520e8a100721b8a462f9850c6462f03b9b103b808018bd52bc8b440cd215888 }


condition:
	$a0
}