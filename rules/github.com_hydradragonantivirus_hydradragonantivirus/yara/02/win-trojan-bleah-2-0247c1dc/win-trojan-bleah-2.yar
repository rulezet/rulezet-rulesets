rule Win_Trojan_Bleah_2
{
strings:
	$a0 = { 04fabe007c8ed78be68edfa1220080fc9f743ba3067ca12000a3047cc4064c00a3087c8c060a }


condition:
	$a0
}