rule Win_Spyware_4718_1
{
strings:
	$a0 = { 7061726d6f722e65786500ffffffff0b0000004d41494c4d4f4e2e45584500ffffffff0a0000004b41565046572e45 }


condition:
	$a0
}