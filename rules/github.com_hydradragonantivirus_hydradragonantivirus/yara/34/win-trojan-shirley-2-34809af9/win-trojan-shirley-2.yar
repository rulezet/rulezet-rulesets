rule Win_Trojan_Shirley_2
{
strings:
	$a0 = { 874bcd213d636675662ea10e0e8cdb01d80510008ed02e }


condition:
	$a0
}