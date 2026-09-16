rule Win_Trojan_Dutch_Tiny_4
{
strings:
	$a0 = { ac080281c50301e80200eb38608b9c0a0281c65501b9b300d1e973014e8bfead33c3abe2fa61c3 }


condition:
	$a0
}