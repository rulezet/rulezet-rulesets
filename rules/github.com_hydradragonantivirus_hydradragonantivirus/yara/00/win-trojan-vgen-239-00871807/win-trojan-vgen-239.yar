rule Win_Trojan_VGEN_239
{
strings:
	$a0 = { e08eb6f4e90800505b8ae5bb8230c37508515a86fb505b86d6b9f975535ae800005d81ed2201e8deffbf050e750ab4 }


condition:
	$a0
}