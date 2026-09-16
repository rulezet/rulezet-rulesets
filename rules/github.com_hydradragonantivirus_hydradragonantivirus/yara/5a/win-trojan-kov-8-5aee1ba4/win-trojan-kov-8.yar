rule Win_Trojan_KOV_8
{
strings:
	$a0 = { b432b0f086e0cd210bc0744333db8edbbe83008dbe????46fca5a50e0e1f58b91500488ed8fec3807fff5a7522 }


condition:
	$a0
}