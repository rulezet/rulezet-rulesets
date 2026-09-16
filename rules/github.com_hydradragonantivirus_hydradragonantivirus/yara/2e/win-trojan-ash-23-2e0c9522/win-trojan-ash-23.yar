rule Win_Trojan_Ash_23
{
strings:
	$a0 = { 5d81ed0c01e80500eb309039368b9617018db64601b98e01311483c602e2f9c3b42ccd2189961701e8e2ffb440 }


condition:
	$a0
}