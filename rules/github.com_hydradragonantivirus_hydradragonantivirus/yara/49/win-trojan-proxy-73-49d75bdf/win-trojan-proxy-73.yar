rule Win_Trojan_Proxy_73
{
strings:
	$a0 = { 535681c6fbe1f16033f78bf65e52ba2cbcd6035a7b005b5951b90647327b7a00b97189bcf0596003fa81d3aec74a848bf874 }


condition:
	$a0
}