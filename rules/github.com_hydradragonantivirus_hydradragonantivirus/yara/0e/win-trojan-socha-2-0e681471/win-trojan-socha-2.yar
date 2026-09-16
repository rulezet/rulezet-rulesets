rule Win_Trojan_Socha_2
{
strings:
	$a0 = { f5ff268b054747263305474726330547472633058d36 }


condition:
	$a0
}