rule Win_Trojan_B_48
{
strings:
	$a0 = { 0103b90200ba8000bb0002cd13bebe03bfbe01b92100f3a52ec606b00180b80103b90100ba8000 }


condition:
	$a0
}