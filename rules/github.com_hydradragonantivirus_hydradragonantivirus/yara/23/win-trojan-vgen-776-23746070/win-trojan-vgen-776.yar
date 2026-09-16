rule Win_Trojan_VGEN_776
{
strings:
	$a0 = { b800008db61701b962012e3104d1c083c602e2f68c86fb038b96d7038b86d903b91000f7f18bd8b44acd210e58 }


condition:
	$a0
}