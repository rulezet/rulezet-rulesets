rule Win_Trojan_OneHalf_8
{
strings:
	$a0 = { 781b3251f788a5c2620d284f91b24be80427c6659bbc51fe1e39dc83a5c617f451b38a69cc200dea4b95f057361a63c0 }


condition:
	$a0
}