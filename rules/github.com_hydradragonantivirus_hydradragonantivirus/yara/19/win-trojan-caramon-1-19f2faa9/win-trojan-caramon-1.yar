rule Win_Trojan_Caramon_1
{
strings:
	$a0 = { 81ed0701b42ccd2180fd08753280f90f752d8d96f801b409cd21b9030051b4098d960802cd21b42ccd2186f7fec7cd }


condition:
	$a0
}