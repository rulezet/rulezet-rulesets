rule Win_Trojan_SdBot_2087
{
strings:
	$a0 = { 11647c7faea6babe2565e7ccc43aa434de9948a2629de8f753247bb64cae642c5b688645a0ad629a9e8cff22da0c9e2fa7cdc14c8b005d11ce5ffd2965158c2280f38defcd8f1ecacd516ba2e5a910abd0d9 }


condition:
	$a0
}