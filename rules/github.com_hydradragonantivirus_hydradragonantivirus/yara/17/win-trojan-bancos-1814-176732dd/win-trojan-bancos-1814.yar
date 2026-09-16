rule Win_Trojan_Bancos_1814
{
strings:
	$a0 = { 854b41f0c3286aed3fb152212078bf8f58f2ba5536388e659e6c2ee7b35f04b8db7f88360de1ba6140d64d943d63879407e797811fd9fabcae3587b039cf7efa3313d42bcadc }


condition:
	$a0
}