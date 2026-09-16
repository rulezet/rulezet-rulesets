rule Win_Trojan_Faroot_1
{
strings:
	$a0 = { 83ec04892c248bec83ec3cff750858ff700c588365f80083ec04538f042483c4fc893424578d5d }


condition:
	$a0
}