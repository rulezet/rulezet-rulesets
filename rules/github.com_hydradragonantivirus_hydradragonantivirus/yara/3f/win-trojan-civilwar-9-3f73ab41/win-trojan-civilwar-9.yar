rule Win_Trojan_CivilWar_9
{
strings:
	$a0 = { e800005d81ed0601bf00018db6d40157a4a58d96da01e8740033c9b44e8d96ce01cd21725cb8023d8d96f801cd218bd8b43f8d96d401b90300cd218b8ed5018b }


condition:
	$a0
}