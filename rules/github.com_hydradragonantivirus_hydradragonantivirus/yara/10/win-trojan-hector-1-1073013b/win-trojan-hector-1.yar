rule Win_Trojan_Hector_1
{
strings:
	$a0 = { 5b83eb03fcc787980000018db7aa00bf0001b90600f3a453b4cd32c9cd215b80f90273508c }


condition:
	$a0
}