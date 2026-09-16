rule Win_Trojan_Win_21
{
strings:
	$a0 = { 28064300e8b33effffe8aa59fdff8be55dc30000ffffffff11000000784c696e6b204c6f6f6b657220312e3061 }


condition:
	$a0
}