rule Win_Trojan_AAEH_15
{
strings:
	$a0 = { 2d433030302d636d6e78 }

	$a1 = { eb0cff157410400089859cfdffff6a016a018b95c4feffffa12ce041008d0c9051e83e8dfeff8985e4feffffff154010 }


condition:
	$a0 and $a1
}