rule Win_Trojan_Bugbear_6
{
strings:
	$a0 = { a8d6868682a8d65218edf506e5c9ebebed821ee7ede9822eede7fb121800e5fb18e7ef8244edebede7001a6ef506e5c9ed6e8282508216f9e5fb82e718fbf9e7ef181a821ee7ede982fb121882 }


condition:
	$a0
}