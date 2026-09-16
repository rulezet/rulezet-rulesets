rule Win_Trojan_Clicker_71
{
strings:
	$a0 = { 3e0f2a042455575653e80d0000006b65726e656c33322e646c6c0068706586b1e8e8000000ffd0e8 }


condition:
	$a0
}