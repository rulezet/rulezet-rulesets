rule Win_Trojan_Sdconsent_1
{
strings:
	$a0 = { 53445f323031332049732052756e6e696e6721 }

	$a1 = { 63657274323031332e646174 }

	$a2 = { 6364636f6e666967696e666f2e646174 }

	$a3 = { 73646261636b696e666f2e646c6c }

	$a4 = { 636f6e73656e742e }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}