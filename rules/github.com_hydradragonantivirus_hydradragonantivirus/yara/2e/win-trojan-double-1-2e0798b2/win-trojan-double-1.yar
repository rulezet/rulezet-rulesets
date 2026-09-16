rule Win_Trojan_Double_1
{
strings:
	$a0 = { b989028b1e1303b440cd21e84500721d2bc92bd28b1e1303b80042cd21720eba1503b90300 }


condition:
	$a0
}