rule Win_Trojan_ErrorVirus_1
{
strings:
	$a0 = { 1606c000a118063d00ff770681061806c000b43fba00012b16b105b9bf04030eb105fec4cd21 }


condition:
	$a0
}