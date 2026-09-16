rule Win_Trojan_W_282
{
strings:
	$a0 = { 2bc999cd21b440b9a4052bd2cd218f0698038f069603b440b90a00ba9a05cd21b43ecd21c3 }


condition:
	$a0
}