rule Win_Trojan_Icelandic_3
{
strings:
	$a0 = { 242e8f063b03902e8f06 }


condition:
	$a0
}