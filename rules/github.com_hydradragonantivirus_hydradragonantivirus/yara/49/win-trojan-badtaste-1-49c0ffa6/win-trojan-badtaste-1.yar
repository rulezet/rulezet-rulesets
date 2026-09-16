rule Win_Trojan_BadTaste_1
{
strings:
	$a0 = { 4b7509558bec836606fe5dcf80fc4b74123d003d740d }


condition:
	$a0
}