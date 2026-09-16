rule Win_Trojan_Vienna_16
{
strings:
	$a0 = { 14ff07b901008b1e1a01ba1c01b440cd217216ebe1a14201a30301b4408b1e1a01b93a01ba }


condition:
	$a0
}