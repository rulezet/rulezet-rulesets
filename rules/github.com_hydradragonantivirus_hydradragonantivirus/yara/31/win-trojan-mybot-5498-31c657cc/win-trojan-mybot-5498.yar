rule Win_Trojan_Mybot_5498
{
strings:
	$a0 = { 742b52cb6e7292adc231303992dbdef5c05d76a3ce7dff0606d8763d734117a47b65b752a54adbdf152a6355cac38d2b97aa91b5abb5268ac95b245ea6b5fc97c940bd24c8b0 }


condition:
	$a0
}