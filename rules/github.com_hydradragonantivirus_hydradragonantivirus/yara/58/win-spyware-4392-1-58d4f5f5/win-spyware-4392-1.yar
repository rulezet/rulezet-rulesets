rule Win_Spyware_4392_1
{
strings:
	$a0 = { 55508bc483c004c70000d0400058c390e7107321 }


condition:
	$a0
}