rule Win_Trojan_Kode_5
{
strings:
	$a0 = { 568b7401bfd80103fe8b058a4d02bf00018905884d02b44ebacf0103d6cd217303e99500b443b000ba9e00cd }


condition:
	$a0
}