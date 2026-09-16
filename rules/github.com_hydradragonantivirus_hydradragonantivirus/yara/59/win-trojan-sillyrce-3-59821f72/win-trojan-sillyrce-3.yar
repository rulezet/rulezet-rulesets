rule Win_Trojan_SillyRCE_3
{
strings:
	$a0 = { 011e33c08ec0bf000257fcaf5f751756b923012ef3a4be84005626a526a55fb85502ab91ab5e0781c64d00580be4 }


condition:
	$a0
}