rule Win_Trojan_Graybird_9
{
strings:
	$a0 = { 742ca1b0e248008b00e819003df8506a01a1cce048008b00e819003df88bc8ba4cbd4800b801000080e819056460 }


condition:
	$a0
}