rule anti_debug__RDG_OEP_Signature_Spoofing__8_byt_6_
{
strings:
	$a0 = { 0bb666b122b7 }

condition:
	$a0
}