rule Win_Trojan_Gotcha_4
{
strings:
	$a0 = { da74585251535056571e063d006c744280fc567426 }


condition:
	$a0
}