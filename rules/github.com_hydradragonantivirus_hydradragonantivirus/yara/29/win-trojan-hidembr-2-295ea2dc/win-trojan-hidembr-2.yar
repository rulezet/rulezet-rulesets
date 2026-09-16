rule Win_Trojan_Hidembr_2
{
strings:
	$a0 = { fa33c08ed88ed0be007c8bde33ff8be6fbff0e1304a11304b106d3e08ec050b82a0050fcb90002f3a4cb33c98ec1b80102b102ba8000cd13 }


condition:
	$a0
}