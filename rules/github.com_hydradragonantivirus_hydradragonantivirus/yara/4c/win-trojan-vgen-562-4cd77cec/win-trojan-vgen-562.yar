rule Win_Trojan_VGEN_562
{
strings:
	$a0 = { 368b2d81ed03010e1fe89f038cc00510002e0186ac012e0186ae0106b87979cd213d5269744fb44abbffffcd2183 }


condition:
	$a0
}