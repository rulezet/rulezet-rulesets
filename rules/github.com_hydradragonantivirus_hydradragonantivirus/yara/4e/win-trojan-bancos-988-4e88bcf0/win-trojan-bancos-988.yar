rule Win_Trojan_Bancos_988
{
strings:
	$a0 = { 7283dcd7a89ce8f960577e2240830bfc6ed7fa219ce7b9c74f2f260d4c76a61eaddab3c547ab469395ea8ac2bf76d7fe97621ab327bdfdc19bf2f9fe38a29251 }


condition:
	$a0
}