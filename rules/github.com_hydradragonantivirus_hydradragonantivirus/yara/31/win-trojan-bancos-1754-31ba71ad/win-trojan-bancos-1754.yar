rule Win_Trojan_Bancos_1754
{
strings:
	$a0 = { d22f24ad07813c3ef82f8c917b407395125bdc26787d7a18444d9a03bc519726b7447f9c541b94d27be5aecd800fb4a88b6f5b827aed39dfddff31b277b3a55d6ae9e648225e }


condition:
	$a0
}