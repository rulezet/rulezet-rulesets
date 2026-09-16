rule Win_Downloader_23198_1
{
strings:
	$a0 = { 56568d85fcfeffff50ff350030400056e89500000085c07c0f6a058d85fcfeffff50ff150c20400056ff1508204000cc }


condition:
	$a0
}