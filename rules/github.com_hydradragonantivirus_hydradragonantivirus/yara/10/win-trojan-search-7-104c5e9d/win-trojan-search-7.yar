rule Win_Trojan_Search_7
{
strings:
	$a0 = { ffbd00015533edc30bdb7419b5008a8e4702b801578b }


condition:
	$a0
}