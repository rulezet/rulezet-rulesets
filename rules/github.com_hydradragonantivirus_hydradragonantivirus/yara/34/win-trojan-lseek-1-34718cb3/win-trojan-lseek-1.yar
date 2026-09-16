rule Win_Trojan_Lseek_1
{
strings:
	$a0 = { 2ea186018cdb03c32ea37e012ea188012ea382010e1fe8c403ba6406e80601720d1e07be7e06bf8c06e83b00eb }


condition:
	$a0
}