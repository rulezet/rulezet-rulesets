rule Win_Trojan_Gen_164
{
strings:
	$a0 = { ed01c8020200c606560600bf7b170e57bf56041e5768ff009a100ced016a00bf56051e5768ff009ae709ed018d }


condition:
	$a0
}