rule Win_Trojan_Xed_1
{
strings:
	$a0 = { 8cd315337572f9d4ff8ac481c3fd0f8ed8bb0600813f80 }


condition:
	$a0
}