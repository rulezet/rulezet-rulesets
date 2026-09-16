rule Win_Trojan_Moonlite_1
{
strings:
	$a0 = { e81e00eb2eb8050333dbcd16c3e811008d960301b96e01b440cd21e80300c3 }


condition:
	$a0
}