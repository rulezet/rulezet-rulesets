rule Win_Spyware_Banker_3020
{
strings:
	$a0 = { ab001b876e8f512415d203257449eaf9cdb8c4952a7c44012d824a18d8d91cf097e8076c6451b03ac0af23daa5007dee }


condition:
	$a0
}