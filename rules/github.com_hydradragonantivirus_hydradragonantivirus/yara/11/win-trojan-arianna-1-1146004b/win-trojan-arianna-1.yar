rule Win_Trojan_Arianna_1
{
strings:
	$a0 = { 5e1e0e0e071fb9f60a83ee048bfefdac34f6aae2fa }


condition:
	$a0
}