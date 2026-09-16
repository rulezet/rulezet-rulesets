rule Win_Trojan_CivilWar_22
{
strings:
	$a0 = { 40b902008d962602cd21b80242e83e00558cc80500108ec08d960601b945038bae280281c50301 }


condition:
	$a0
}