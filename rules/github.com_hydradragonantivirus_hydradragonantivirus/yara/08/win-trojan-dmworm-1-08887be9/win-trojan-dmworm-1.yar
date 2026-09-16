rule Win_Trojan_DmWorm_1
{
strings:
	$a0 = { 01b47fcd1680ecb2b90f03bd17002e302245e2fa90529cb9a5db86bbf0cfa15264ba039a9e9530adb0b99535a5b6b9769a957dbd5eb9ba505d3049fd3b }


condition:
	$a0
}