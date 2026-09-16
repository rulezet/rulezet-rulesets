rule Win_Trojan_Agent_34341
{
strings:
	$a0 = { 50e801000000c358870424ff3424834424040ec383ec0450e8 }


condition:
	$a0
}