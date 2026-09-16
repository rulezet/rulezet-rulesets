rule Win_Trojan_ScottsValley_2
{
strings:
	$a0 = { 8bde909081c63200b912082e }


condition:
	$a0
}