rule Win_Trojan_QRabid_1
{
strings:
	$a0 = { 2e803e43020977e0b403b0090e1fbb09012e8a2e44022e8a0e4302b600b202cd132efe064302 }


condition:
	$a0
}