rule Win_Trojan_Falcon_1
{
strings:
	$a0 = { 33f650b8c00707bb33038ed82683afe0000233ffb106268b87e000d3e08ec0fcb9ff00f3a5 }


condition:
	$a0
}