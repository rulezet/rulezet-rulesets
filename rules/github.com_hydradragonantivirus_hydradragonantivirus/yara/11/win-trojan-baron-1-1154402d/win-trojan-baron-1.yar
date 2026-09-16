rule Win_Trojan_Baron_1
{
strings:
	$a0 = { 863bcd8e8073e3a8f4394b34368f861ba88ec6ac800b7d8e268e0b048d9f08bec2bed9350bcfc6ac }


condition:
	$a0
}