rule Win_Trojan_HDZap_2
{
strings:
	$a0 = { ba7000b009ee42ec8ae04ab008ee42ec3d0894722a1e33c08ed8a06c041f3cc077103c807219ba7000b012ee42b000eeebfeb88003b90100ba8000cd13ebe7e9 }


condition:
	$a0
}