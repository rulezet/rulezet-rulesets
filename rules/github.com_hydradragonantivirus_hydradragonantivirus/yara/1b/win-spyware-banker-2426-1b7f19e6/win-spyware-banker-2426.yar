rule Win_Spyware_Banker_2426
{
strings:
	$a0 = { 831340407080dbea0c986aae384dfef4fa8c535cf1f6a9bb2f688f5fe8ad862562a4f2053e992f58e6412e71bf3c6bd23ef142992220492c7cf2fafe040000fa846a5a4f5e9b444d51c0 }


condition:
	$a0
}