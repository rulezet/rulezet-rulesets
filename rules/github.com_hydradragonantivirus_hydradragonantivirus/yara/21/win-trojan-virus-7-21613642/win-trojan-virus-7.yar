rule Win_Trojan_Virus_7
{
strings:
	$a0 = { 24073c007506b44fcd21ebe8b8080003c38bd0b8013dcd21730ab44f33c9cd21721bebd08b }


condition:
	$a0
}