rule Win_Trojan_Leal_1
{
strings:
	$a0 = { 60061e8b2e????8dbe1f0157b9a80089fead[0-4]abe2f8c3 }


condition:
	$a0
}