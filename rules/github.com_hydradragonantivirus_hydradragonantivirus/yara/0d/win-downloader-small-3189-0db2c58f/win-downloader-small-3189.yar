rule Win_Downloader_Small_3189
{
strings:
	$a0 = { 2778865d49d4efd0b2acb6fcbb7c82f81b343b547363d882cbda38455b5a70d8eeb9013a495107284f2e05ff4c2b05234d4a1b606c5f057f50401fd9bdf1350e53b01c3a52f5 }


condition:
	$a0
}