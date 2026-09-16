rule Win_Trojan_Sibylle_1
{
strings:
	$a0 = { 4b75f3505351525657551e061e520e1fe8a7015a1fb8 }


condition:
	$a0
}