rule Win_Trojan_SillyC_117
{
strings:
	$a0 = { 0181c6e4018bd690b41a90cd21b120b44ebade01cd217278b8023d8bd6505883c21e5058cd217268938bd683c2 }


condition:
	$a0
}