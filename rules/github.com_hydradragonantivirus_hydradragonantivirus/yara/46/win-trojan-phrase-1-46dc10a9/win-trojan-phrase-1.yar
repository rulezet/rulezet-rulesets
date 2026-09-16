rule Win_Trojan_Phrase_1
{
strings:
	$a0 = { c08ec0b8341226a3220226290622027402ffe00758b0 }


condition:
	$a0
}