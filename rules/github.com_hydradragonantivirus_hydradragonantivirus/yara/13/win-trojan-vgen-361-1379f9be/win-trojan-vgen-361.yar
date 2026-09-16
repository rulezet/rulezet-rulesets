rule Win_Trojan_VGEN_361
{
strings:
	$a0 = { ffeb0690b8004ccd21e2f6e800005d81ed1301e9b9018db64a018bfee80300eb2490acf6d0d0c8d0c8d0c8d0c8f6 }


condition:
	$a0
}