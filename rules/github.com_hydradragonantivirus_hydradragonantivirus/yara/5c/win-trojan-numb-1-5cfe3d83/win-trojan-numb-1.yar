rule Win_Trojan_Numb_1
{
strings:
	$a0 = { bf00018cde8d54100153068b5b108b4d060155168d31fce30ead93ad03c203038ec0260117 }


condition:
	$a0
}