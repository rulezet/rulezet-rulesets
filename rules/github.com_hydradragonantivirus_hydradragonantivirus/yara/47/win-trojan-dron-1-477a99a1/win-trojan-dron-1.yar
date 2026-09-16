rule Win_Trojan_Dron_1
{
strings:
	$a0 = { d28bdc8cc98ed1bc260052531e068cdd8bc50510002e0106fd03b8aaaacd2181fbaaaa74668bc5488ec0268b1e0300 }


condition:
	$a0
}