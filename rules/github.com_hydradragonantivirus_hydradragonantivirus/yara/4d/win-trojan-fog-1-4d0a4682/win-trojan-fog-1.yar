rule Win_Trojan_Fog_1
{
strings:
	$a0 = { b963031de54290be56ffbd45cff51da8322601bc }


condition:
	$a0
}