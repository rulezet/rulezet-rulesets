rule Win_Trojan_Banker_4629
{
strings:
	$a0 = { 558becb83429fb4fbbe4c621af50e800000000582da81a0000b96d1a0000ba211b0000be00100000bfc053 }


condition:
	$a0
}