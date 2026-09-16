rule Win_Trojan_VGEN_372
{
strings:
	$a0 = { e80803e800008bec8b5e008beb81ed0901b82637cd213d4c377503e858000eb82135cd213e899e53023e8c8655 }


condition:
	$a0
}