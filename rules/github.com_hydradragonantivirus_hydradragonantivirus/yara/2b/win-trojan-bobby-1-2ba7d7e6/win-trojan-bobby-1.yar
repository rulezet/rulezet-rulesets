rule Win_Trojan_Bobby_1
{
strings:
	$a0 = { 81ee0701bb9f0203de8b07a300018b4702a30201b42ccd2180fd1575078d1e00019dffe3b41aba650303d6cd2156 }


condition:
	$a0
}