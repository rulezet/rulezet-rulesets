rule Win_Trojan_Qpa_1
{
strings:
	$a0 = { 060002433afcbafa01b44e33c9cd21721abe9e00bf0202b10df3a4e81a0052ba8000b44fcd215a7202ebe681faf801 }


condition:
	$a0
}