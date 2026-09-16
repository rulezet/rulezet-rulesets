rule Win_Trojan_Bancos_1793
{
strings:
	$a0 = { adf5d684d62e216f5c0f903f1a0c2365d7dacacc9bba7c05753cc6936e158141953e77efb034244de5dff41acba824c5f7f9a777fc684d769aeb609432a9f53ee349cbbe6482 }


condition:
	$a0
}