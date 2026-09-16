rule Win_Trojan_VGEN_112
{
strings:
	$a0 = { e800005d81ed0801b8ad0bcd2181faadde744e8cd8488ed8812e0300f200812e1200f200a112008ed82d0f008ec0c606 }


condition:
	$a0
}