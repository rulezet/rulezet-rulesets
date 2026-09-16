rule Win_Spyware_59867_1
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f675 }

	$a1 = { 776f772e646c6c }

	$a2 = { 776f726c646f667761726372616674 }


condition:
	$a0 and $a1 and $a2
}