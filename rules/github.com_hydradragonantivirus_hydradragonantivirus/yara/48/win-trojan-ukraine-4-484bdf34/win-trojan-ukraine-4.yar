rule Win_Trojan_Ukraine_4
{
strings:
	$a0 = { 5b09b933038bc13104056d4946e2f850538becfabc2901bb00005833c383c300504481fcc00c75f28be55b585057e8 }


condition:
	$a0
}