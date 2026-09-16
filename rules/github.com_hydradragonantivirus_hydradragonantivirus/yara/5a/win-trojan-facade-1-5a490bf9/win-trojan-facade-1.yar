rule Win_Trojan_Facade_1
{
strings:
	$a0 = { 33c0bb007c8ed08be38ed88ec0be4c00bfc27dfca5a5cd1248a31304b106d3e0508ec089de33ffb90001f3a5b871 }


condition:
	$a0
}