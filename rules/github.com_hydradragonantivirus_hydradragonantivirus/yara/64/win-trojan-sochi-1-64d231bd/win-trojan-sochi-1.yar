rule Win_Trojan_Sochi_1
{
strings:
	$a0 = { 02ba8000b90100cd13be12018bfbb97901fcf2a4b90100b80103ba8000cd13b44e33c9ba0301 }


condition:
	$a0
}