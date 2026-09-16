rule Win_Trojan_Awake_2
{
strings:
	$a0 = { 8b848eca81c90b05bd8f8b8e85056b111611910fe804a5db295037a5df2d5028912c9fa72426f6e8 }


condition:
	$a0
}