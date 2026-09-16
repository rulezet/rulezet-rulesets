rule Win_Trojan_Peed_342
{
strings:
	$a0 = { e8010000002058e85900000052ad05 }


condition:
	$a0
}