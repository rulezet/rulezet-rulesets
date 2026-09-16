rule Win_Trojan_Gen_185
{
strings:
	$a0 = { 579add058e00833e5402007417bf5a031e57bf8b040e5731c0509a70068e009add05 }


condition:
	$a0
}