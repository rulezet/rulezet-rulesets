rule Win_Trojan_Slugger_1
{
strings:
	$a0 = { ba0000cd21720eb440b92001ba0001cd21b43ecd21c3803e8d0101750ebf0401b05caab43b }


condition:
	$a0
}