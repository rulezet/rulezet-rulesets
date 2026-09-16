rule Win_Trojan_SillyC_102
{
strings:
	$a0 = { e43dba727426b800424199cd21b601b1d2b440cd218bd78b0e0301b440cd218b0e96008b169800 }


condition:
	$a0
}