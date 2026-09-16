rule Win_Downloader_Small_1559
{
strings:
	$a0 = { 31c07302cd0383ec0831c9890c240f010c248b0c2485c974e783c408e8000000005a83ea2181ea50 }


condition:
	$a0
}