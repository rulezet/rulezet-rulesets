rule Win_Trojan_Y_19
{
strings:
	$a0 = { 6f7368615b4c545d209c0e689a00e9a004c3b003cfb8024299eb0890b800428b16550633c9 }


condition:
	$a0
}