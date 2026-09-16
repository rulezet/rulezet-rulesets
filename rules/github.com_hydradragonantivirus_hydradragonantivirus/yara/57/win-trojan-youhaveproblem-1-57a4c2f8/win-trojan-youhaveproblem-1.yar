rule Win_Trojan_Youhaveproblem_1
{
strings:
	$a0 = { e800005f83ef040e1fc704????c74402????b42fcd21899dfe018bd781c24102b41acd2157be }


condition:
	$a0
}