rule Win_Adware_Lop_203
{
strings:
	$a0 = { 802c220ca5c629e88302595ff94401daa717b4fff27fe97c954103e1246fdbd1da0cc02f753103470904ae3a0b4e193e3a9adab582b99147cd30a0ab }


condition:
	$a0
}