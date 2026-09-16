rule Win_Trojan_Mercury_1
{
strings:
	$a0 = { 803e2f010a7403e930012e803e3c01137404fbe92401b403b0022e8b8c1800b280b600cd13fbe9 }


condition:
	$a0
}