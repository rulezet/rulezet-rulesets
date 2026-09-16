rule Win_Trojan_Vienna_61
{
strings:
	$a0 = { f983c70205030103c189058bfab4402bd1b99602cd }


condition:
	$a0
}