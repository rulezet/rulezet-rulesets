rule Win_Trojan_CountDown_2
{
strings:
	$a0 = { 6e4f77202e2e2e00909090fa99cd26fbc3b42f909090cd21e98401817c1aacf97640e9070190 }


condition:
	$a0
}