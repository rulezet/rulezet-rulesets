rule Win_Trojan_Russel_1
{
strings:
	$a0 = { 0c02061ee6212e8a0483ee038bd6b9840481c62800fc2e8a64012e302446e2f6 }


condition:
	$a0
}