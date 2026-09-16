rule Win_Trojan_Muminki_1
{
strings:
	$a0 = { ba43c16d502457ebb852ba59c16d5324bdeba3529c704e2246efae5277af5577d16d522497779755 }


condition:
	$a0
}