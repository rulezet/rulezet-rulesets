rule Win_Trojan_Stoned_45
{
strings:
	$a0 = { 8f01b80103ba8000cd8872cfe80b00b8010333dbfec1cd88ebc1bebe03bfbe01b92100fcf3a5 }


condition:
	$a0
}