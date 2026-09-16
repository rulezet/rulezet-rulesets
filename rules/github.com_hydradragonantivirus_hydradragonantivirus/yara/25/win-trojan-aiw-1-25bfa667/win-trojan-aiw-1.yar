rule Win_Trojan_Aiw_1
{
strings:
	$a0 = { e800005d81ed0301c686da0200b4f6cd213d325774560e58488ec026a000003c5a740c3c4d7401f4e84f008ec0ebec26 }


condition:
	$a0
}