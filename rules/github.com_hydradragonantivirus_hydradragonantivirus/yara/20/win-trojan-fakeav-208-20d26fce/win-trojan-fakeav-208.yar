rule Win_Trojan_FakeAV_208
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d6d77667562616f622e657865 }


condition:
	$a0
}