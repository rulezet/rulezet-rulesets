rule Win_Trojan_IVP_11
{
strings:
	$a0 = { 408d96bf0359cd217210b002e82900b440b952028d960301cd21b801572e8b8eab032e8b96ad03 }


condition:
	$a0
}