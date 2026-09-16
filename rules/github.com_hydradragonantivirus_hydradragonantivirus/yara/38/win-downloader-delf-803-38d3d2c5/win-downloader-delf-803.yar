rule Win_Downloader_Delf_803
{
strings:
	$a0 = { e824ebffff508b4308e81bebffff506a00e8a7f8ffff85c07570a1847640008b58048b4310ba04514000e846eaffff751b6a016a006a008b430ce8eaeaffff50680c5140006a00e8c1f7ffff }


condition:
	$a0
}