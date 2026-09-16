rule Win_Trojan_VGEN_298
{
strings:
	$a0 = { 9081ed06008db61d01bfff004757a5a4b98000be80008dbe4b01f3a4b40e32d28bf581c65001c6864f015ce8e200c6 }


condition:
	$a0
}