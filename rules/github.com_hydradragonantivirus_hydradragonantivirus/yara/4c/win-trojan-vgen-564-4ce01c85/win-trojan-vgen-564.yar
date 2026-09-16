rule Win_Trojan_VGEN_564
{
strings:
	$a0 = { 368b2d81ed03010e1fe89a038cc00510002e0186ab012e0186ad0106b87979cd213d5269744eb44abbffffcd2183 }


condition:
	$a0
}