rule Win_Trojan_Gen_226
{
strings:
	$a0 = { 902e1e578dbe00ff165731c0509afd0555009a3f045500e894ffbf902e1e57bf70051e57b89013 }


condition:
	$a0
}