rule Win_Trojan_Mephisto_3
{
strings:
	$a0 = { 01b9b5018bb67f0431354747e2fa59c3cd21e8e7ffe9c5fd }


condition:
	$a0
}