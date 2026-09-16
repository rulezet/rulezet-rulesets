rule Win_Trojan_Stoned_72
{
strings:
	$a0 = { 02b90700890e8401b80103ba8000cd137214be9003bf9001b97200f3a4b8010333dbfec1cd13 }


condition:
	$a0
}