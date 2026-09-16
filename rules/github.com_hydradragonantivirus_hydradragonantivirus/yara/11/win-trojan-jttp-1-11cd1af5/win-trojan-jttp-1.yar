rule Win_Trojan_JTTP_1
{
strings:
	$a0 = { 09cd2158eb1a903d004b7514e8ac01e846007306e80e00 }


condition:
	$a0
}