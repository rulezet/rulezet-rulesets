rule Win_Trojan_DiskInt_1
{
strings:
	$a0 = { f5ab268c0d5fb0abab268c0d8e462c8b }


condition:
	$a0
}