rule Win_Trojan_VCC_33
{
strings:
	$a0 = { 011fe90000cd2180fa0074f98896ca01e80f00b440b9fe018d960001cd21e80100c3b92e01 }


condition:
	$a0
}