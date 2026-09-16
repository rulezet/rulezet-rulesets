rule Win_Trojan_Hupigon_519
{
strings:
	$a0 = { 480bcb7f73f0136a44c1bc694132ccb44e06110b64737abe7d536fea53b0ff786384148eba1dcf3c039e330ba5c6d766e889ccfb65bd65ba6ce401e3a3c2246bd38e6435641b5fb44124d1dabe02 }


condition:
	$a0
}