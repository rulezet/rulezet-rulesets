rule Win_Trojan_Surrender_3
{
strings:
	$a0 = { e8c400b440badf03b90300cce98d0080 }


condition:
	$a0
}