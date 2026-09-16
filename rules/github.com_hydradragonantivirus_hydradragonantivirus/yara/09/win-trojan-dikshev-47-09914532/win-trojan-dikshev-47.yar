rule Win_Trojan_Dikshev_47
{
strings:
	$a0 = { 652a8bd6b44ecd21bf9e0057b82e5bf2ae66c705434f4d005a8bcee80000cd2193b4408bd6 }


condition:
	$a0
}