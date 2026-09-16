rule Win_Trojan_Disruptor_1
{
strings:
	$a0 = { be40008a042e2a063e002e02063f002efe0e3e002efe063f00b1012ed20e3e002ed2063f002e80363e007f2e8036 }


condition:
	$a0
}