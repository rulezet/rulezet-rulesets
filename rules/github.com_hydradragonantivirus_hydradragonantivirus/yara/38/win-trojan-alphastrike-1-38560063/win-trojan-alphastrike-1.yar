rule Win_Trojan_AlphaStrike_1
{
strings:
	$a0 = { 8b3602002bf781fe0010e800008bec8b6e00fcb85844cd21720f268e5f0ebe0b00eb469c60 }


condition:
	$a0
}