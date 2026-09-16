rule Win_Trojan_Dikshev_48
{
strings:
	$a0 = { 2aba00018beab44ecd21bf9e0057b82e5bf2ae66c705434f4d005a8bcde80000cd2193b4408bd5 }


condition:
	$a0
}