rule Win_Trojan_Clicker_27
{
strings:
	$a0 = { 301040e2fb8d0500304000b967000000b2aa301040e2fbeb08535353e8aa060000 }


condition:
	$a0
}