rule Win_Trojan_Kode4_10
{
strings:
	$a0 = { cd2181fb69697503eb1d900e1fb82135cd21bf0301891d8c4502ba4a01b82125cd21ba0000cd27be00018b4401 }


condition:
	$a0
}