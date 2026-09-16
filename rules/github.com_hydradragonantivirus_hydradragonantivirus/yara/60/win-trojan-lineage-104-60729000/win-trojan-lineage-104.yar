rule Win_Trojan_Lineage_104
{
strings:
	$a0 = { 4ad6014007d6dacdbf6a10fe8797a804248ea65c430ac695cc2c4c1eddde742fde271ff3ef96f68ba29450c7b9658793be50ec4b22f33d591ef64c300b1e6bbe89a4e465 }


condition:
	$a0
}