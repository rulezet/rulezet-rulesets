rule Win_Trojan_ExeHeader_10
{
strings:
	$a0 = { 35cd2181fbae0074758cd82d01008ed8803e00005a740bb448bb2000cd21725eeb0fbb2000291e0300a112002b }


condition:
	$a0
}