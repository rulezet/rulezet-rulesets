rule Win_Trojan_Small_4136
{
strings:
	$a0 = { eb01c38d1d997ef0fd81c36715650289dd8dbb7c070000be3faaa70081f62636 }


condition:
	$a0
}