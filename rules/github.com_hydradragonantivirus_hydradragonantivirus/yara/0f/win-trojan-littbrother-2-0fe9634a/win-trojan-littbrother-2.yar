rule Win_Trojan_LittBrother_2
{
strings:
	$a0 = { 2153060e1fba9101b42550cd21c5168d02b43cb90300cd21930e1fb98901ba0001b440cd21b43e }


condition:
	$a0
}