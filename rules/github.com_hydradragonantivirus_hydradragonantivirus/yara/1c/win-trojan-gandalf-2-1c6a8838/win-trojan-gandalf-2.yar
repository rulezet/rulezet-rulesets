rule Win_Trojan_Gandalf_2
{
strings:
	$a0 = { 8ed8803e00005a753aa103002d0001a303008bd88cc003c38ec0b9aa018cd8408ed8be0001bf0001f3a48ed9be }


condition:
	$a0
}