rule Win_Trojan_OneHalf_19
{
strings:
	$a0 = { 4861b2eed638ad843bf709019d1400a1e2088dbe5e68c1b69d077d9067c1af }


condition:
	$a0
}