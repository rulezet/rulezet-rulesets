rule Win_Trojan_Jak_2
{
strings:
	$a0 = { ed0300b41a8d967700cd21e82900cd202a2e636f6d005b4a614b2e536d616c6c5d005b4a65726b314e202f204449 }


condition:
	$a0
}