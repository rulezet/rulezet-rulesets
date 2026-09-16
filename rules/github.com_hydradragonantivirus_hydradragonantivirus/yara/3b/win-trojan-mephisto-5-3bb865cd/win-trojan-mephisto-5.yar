rule Win_Trojan_Mephisto_5
{
strings:
	$a0 = { 01b9b9018bb6860431354747e2fa59c3cd21e8e7ffe9bdfdb003cf }


condition:
	$a0
}