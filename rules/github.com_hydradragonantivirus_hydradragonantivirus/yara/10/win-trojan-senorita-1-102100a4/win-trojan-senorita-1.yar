rule Win_Trojan_Senorita_1
{
strings:
	$a0 = { 9c2e89360001e8[1-5]e800005e515750b9290381ee????e8[1-5]5f2e8a052e300446e2fa }


condition:
	$a0
}