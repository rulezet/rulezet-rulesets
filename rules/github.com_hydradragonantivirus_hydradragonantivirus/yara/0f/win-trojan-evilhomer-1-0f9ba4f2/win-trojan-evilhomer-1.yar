rule Win_Trojan_EvilHomer_1
{
strings:
	$a0 = { cc01b440b9ce008d960601cd21b800429933c9cd21b4 }


condition:
	$a0
}