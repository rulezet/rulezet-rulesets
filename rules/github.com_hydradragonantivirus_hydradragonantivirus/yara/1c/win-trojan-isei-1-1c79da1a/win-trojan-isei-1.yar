rule Win_Trojan_Isei_1
{
strings:
	$a0 = { c0cd110bc07504b44ccd218b6efa8d76fab8440b03c6509c53bb6200b940082e8b84c8102e }


condition:
	$a0
}