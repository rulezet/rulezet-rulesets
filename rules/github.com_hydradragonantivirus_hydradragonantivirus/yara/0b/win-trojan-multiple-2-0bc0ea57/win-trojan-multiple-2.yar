rule Win_Trojan_Multiple_2
{
strings:
	$a0 = { 2504e8fa008d94cd03cd21e9ebfee8a600b42acd2180fa05750ab002b9000199cd26ebfe }


condition:
	$a0
}