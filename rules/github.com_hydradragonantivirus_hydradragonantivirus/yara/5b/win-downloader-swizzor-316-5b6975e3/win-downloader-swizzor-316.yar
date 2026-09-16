rule Win_Downloader_Swizzor_316
{
strings:
	$a0 = { 397754a82fa7f34ea515e317a6d266fa394c6638a7b269417f7e944a5ec26e0a9daedc0ef73e21044277d03626bf2700 }


condition:
	$a0
}