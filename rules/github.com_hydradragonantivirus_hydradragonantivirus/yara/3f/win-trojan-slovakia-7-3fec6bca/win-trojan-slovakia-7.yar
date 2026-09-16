rule Win_Trojan_Slovakia_7
{
strings:
	$a0 = { a5fdfc81c7fefab9af03b9b001e8dcffb980d58bfa8aa5fdfc81c76afdb96661b9d505e8 }


condition:
	$a0
}