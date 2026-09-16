rule Win_Trojan_W_381
{
strings:
	$a0 = { 02b43cb90300cd218bd8b440ba??01b93700[0-1]cd21ba??02b43cb90300cd218bd8b440ba0001b9 }


condition:
	$a0
}