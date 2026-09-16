rule Win_Trojan_BootExe_2
{
strings:
	$a0 = { 01b80102cd1372f0e8de005acbb4f0cd1380fc1974108cd8488ed82916030029161200e8c300 }


condition:
	$a0
}