rule Win_Trojan_Coda_1
{
strings:
	$a0 = { 505351521e068cd80510002e014602b8dec0cd213cda7503e93a018e062c0033ffb8434faf7512b84d53af750c }


condition:
	$a0
}