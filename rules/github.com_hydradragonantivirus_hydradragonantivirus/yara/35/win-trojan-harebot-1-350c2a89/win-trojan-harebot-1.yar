rule Win_Trojan_Harebot_1
{
strings:
	$a0 = { 6f643f3f73505e5b73565d4d5e4d467e3f3f3f3f785a4b6f4d505c7e5b5b4d5a }

	$a1 = { 736579652e636f6d3b6675636b627269616e6b72 }


condition:
	$a0 and $a1
}