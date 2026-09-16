rule Win_Trojan_Spider_2
{
strings:
	$a0 = { 180183ec01b00950bf2b011e579a1a019500b00950b800008cca52509a49019500c4066803 }


condition:
	$a0
}