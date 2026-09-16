rule Win_Trojan_Rukap_59
{
strings:
	$a0 = { 8e79d03e3745dfb23e2deeeec2306b747681146ea90d9fc317e65899d8de7c6faf85c27da38e2dc6e59a3d264f8962ffe9bff983b5d1bee7a124a48a5d0bc88b8d54938a4cf1548f }


condition:
	$a0
}