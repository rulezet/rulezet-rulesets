rule Win_Trojan_Antitrace_2
{
strings:
	$a0 = { 2135cd218c063401891e3201ba1901b425cd21ba3601cd271e5633f68edec5740466ff3466c704ca020000668f045e1fea }


condition:
	$a0
}