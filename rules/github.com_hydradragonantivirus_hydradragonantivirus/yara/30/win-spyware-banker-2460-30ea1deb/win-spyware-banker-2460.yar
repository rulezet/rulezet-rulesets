rule Win_Spyware_Banker_2460
{
strings:
	$a0 = { f91a4c4dd97701f5999c4b658362a4342133995ebd2c8c53f59b5d4d64631d652524dab2f716be1f4a4dc4fd9061b29456d0b54dfec06de8f4905efcb432c26de266b77d5fc6becf7a75 }


condition:
	$a0
}