rule Win_Trojan_Sejese_1
{
strings:
	$a0 = { c78528ffffffdc3f4000c78520ffffff08000000c78518ffffffb0404000c78510ffffff080000006a008d9520ffffff }


condition:
	$a0
}