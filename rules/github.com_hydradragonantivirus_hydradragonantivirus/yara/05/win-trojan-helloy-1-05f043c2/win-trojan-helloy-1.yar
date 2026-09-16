rule Win_Trojan_Helloy_1
{
strings:
	$a0 = { 81ee0301c3ba8000b41acd21b44eba160203d6b90000cd217219b43db002ba9e00cd2189841c02bf9a008b058984 }


condition:
	$a0
}