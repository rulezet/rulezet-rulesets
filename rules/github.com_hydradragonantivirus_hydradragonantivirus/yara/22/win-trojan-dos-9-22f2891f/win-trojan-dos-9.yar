rule Win_Trojan_DOS_9
{
strings:
	$a0 = { 522e242424005589e5b8040a9acd02ff0081ec040a8dbe7cf716578dbefcf5165731c0509a }


condition:
	$a0
}