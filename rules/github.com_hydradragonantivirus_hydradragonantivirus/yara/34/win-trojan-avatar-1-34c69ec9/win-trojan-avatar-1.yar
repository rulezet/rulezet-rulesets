rule Win_Trojan_Avatar_1
{
strings:
	$a0 = { 81ed0300b8ffa02bdbcd210681fbffa07458b82135cd21899e62028c8664028cd8488ec026803e00005a756326832e }


condition:
	$a0
}