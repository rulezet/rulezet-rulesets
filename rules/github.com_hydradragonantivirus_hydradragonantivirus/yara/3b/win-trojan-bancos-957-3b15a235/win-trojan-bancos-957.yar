rule Win_Trojan_Bancos_957
{
strings:
	$a0 = { e7fa1577fc6ee5b147df3dfe5e2479a7e084e67695eaae20ea2189046e3be035e2370f8ef91cef7d014b5d7002fd1572e615c37d6843686658ca779c8bb605da81908babcda4d5b6a572f0ff08ef }


condition:
	$a0
}