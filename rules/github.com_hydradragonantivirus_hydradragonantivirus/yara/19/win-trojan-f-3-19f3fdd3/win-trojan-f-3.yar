rule Win_Trojan_F_3
{
strings:
	$a0 = { c0bb007c8ed08be38ed88ec05053be4c00bfd17dfca5a5cd1248a31304b106d3e0 }


condition:
	$a0
}