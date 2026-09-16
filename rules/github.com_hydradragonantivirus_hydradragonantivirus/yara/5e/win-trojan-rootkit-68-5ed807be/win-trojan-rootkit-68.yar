rule Win_Trojan_Rootkit_68
{
strings:
	$a0 = { 601bd0c1e913e907000000b8204ffeb803ca68f0150000c1e808bac049e76e81 }


condition:
	$a0
}