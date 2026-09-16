rule Win_Trojan_SP3_1
{
strings:
	$a0 = { 44beb502bfb500b90600f3a67437c606af0202ff06a902b80103bb0000b90500ba8000cd13 }


condition:
	$a0
}