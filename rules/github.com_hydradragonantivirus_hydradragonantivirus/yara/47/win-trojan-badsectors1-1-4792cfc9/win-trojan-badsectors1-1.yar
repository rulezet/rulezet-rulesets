rule Win_Trojan_BadSectors1_1
{
strings:
	$a0 = { 213c02721f1e33c08ed8a113041fb106d3e08ec00e1fbe5601bf0000b90b00fcf3a6753c0e }


condition:
	$a0
}