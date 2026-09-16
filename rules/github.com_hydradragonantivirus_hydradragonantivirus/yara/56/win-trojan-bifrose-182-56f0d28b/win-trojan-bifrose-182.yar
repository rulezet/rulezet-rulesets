rule Win_Trojan_Bifrose_182
{
strings:
	$a0 = { 54b00cf99877e6cf0a90f4ebe9fc00a23f3aaf28457f8b00f216617f19e9e19c0084f4b8d75fef41070008c44b203bf00ae1005d330e1ce00152d370ab002ae63cf9ff29 }


condition:
	$a0
}