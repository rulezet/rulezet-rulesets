rule Win_Trojan_Trojan_144
{
strings:
	$a0 = { 8cdb8ec383c3100e582d10008ed8019c2001ffb42001ffb4 }


condition:
	$a0
}