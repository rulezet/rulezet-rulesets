rule Win_Trojan_Mybot_7237
{
strings:
	$a0 = { 0bc8d42c3b18e35b2001c9ab32f9ebe18e6a2c8f491795bb06b554de4bd2ecbd6d02a01d6165633a8a631a0e163ac75e876bd1916cd0f72fdfcc3bcb525795d2b239406e8b17a032f9d5489f9b2f }


condition:
	$a0
}