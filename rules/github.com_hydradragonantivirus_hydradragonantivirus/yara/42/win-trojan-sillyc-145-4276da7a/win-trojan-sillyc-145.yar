rule Win_Trojan_SillyC_145
{
strings:
	$a0 = { 8bd681ea0b00b90401cd2158724583e803538bde81eb0b002e894701c607e95b2bd22bc9b800 }


condition:
	$a0
}