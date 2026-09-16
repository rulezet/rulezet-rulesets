rule Win_Trojan_Agent_31470
{
strings:
	$a0 = { 72747365656b2e62697a00ad6db7c11477002e751878171cdba68bff63682e636f6d2f0005100160ea073adffd }


condition:
	$a0
}