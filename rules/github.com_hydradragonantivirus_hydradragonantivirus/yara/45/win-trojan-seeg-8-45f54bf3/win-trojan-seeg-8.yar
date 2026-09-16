rule Win_Trojan_Seeg_8
{
strings:
	$a0 = { 040052f7e15a2bf88b0580ec7232c003d05858e800005d81ed2102eb0633dbeb02b7228db65502 }


condition:
	$a0
}