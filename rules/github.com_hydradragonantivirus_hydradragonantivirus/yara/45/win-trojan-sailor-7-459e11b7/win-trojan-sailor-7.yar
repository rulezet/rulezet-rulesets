rule Win_Trojan_Sailor_7
{
strings:
	$a0 = { 0300a3fd03b43ffec4b94403ba0001cd2132c0b44299b90000cd21b90400b43ffec4bafc03cd21 }


condition:
	$a0
}