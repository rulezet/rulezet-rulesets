rule Win_Trojan_Claire_1
{
strings:
	$a0 = { a101010ac48db607018dbef0033004463bf776f9e9ebfe }


condition:
	$a0
}