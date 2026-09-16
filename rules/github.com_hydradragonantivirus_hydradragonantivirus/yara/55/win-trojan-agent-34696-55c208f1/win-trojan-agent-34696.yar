rule Win_Trojan_Agent_34696
{
strings:
	$a0 = { 558becb85ac1c269bbac32a0a150e800000000582da81a0000b96d1a0000ba211b0000be00100000bf }


condition:
	$a0
}