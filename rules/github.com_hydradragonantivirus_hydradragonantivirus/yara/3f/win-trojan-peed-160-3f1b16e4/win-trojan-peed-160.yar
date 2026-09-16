rule Win_Trojan_Peed_160
{
strings:
	$a0 = { e8670000005589e55389e38d67045089dc5b89d88b5d086bdb0283eb24c9c2040089e001 }


condition:
	$a0
}