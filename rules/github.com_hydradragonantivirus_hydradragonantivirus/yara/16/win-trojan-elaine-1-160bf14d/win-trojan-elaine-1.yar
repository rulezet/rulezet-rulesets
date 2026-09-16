rule Win_Trojan_Elaine_1
{
strings:
	$a0 = { 71052e89167305e81f00c3e80d00b4408d160001b9670490cd21c3b800428b0e73058b167105 }


condition:
	$a0
}