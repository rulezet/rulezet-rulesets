rule Win_Trojan_Small_5317
{
strings:
	$a0 = { 81158a7a62e5db2f8ac01e230985cec44c701ac498c81f04ce67c27fdfabae2f8a438376e0428270d41e81ecdfc8367edb108c78013ed2acef4bdaa4cd7fd9e885f492290f8a5362763de5a23a4b }


condition:
	$a0
}