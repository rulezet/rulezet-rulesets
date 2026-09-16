rule Win_Trojan_Mini_66
{
strings:
	$a0 = { 20ba4701cd21b8023dba9e00cd21c5364d019392b151b43fcd215133c9b8 }


condition:
	$a0
}