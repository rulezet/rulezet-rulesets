rule Win_Trojan_Kwok_1
{
strings:
	$a0 = { a013073c01740cb42acd2180fa017403e9f501b40fcd102e883ef701b91000bef801ba00002e8b04b9190051b90500 }


condition:
	$a0
}