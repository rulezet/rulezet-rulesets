rule Win_Trojan_DSME_4
{
strings:
	$a0 = { b6d6eb0f1e1810eb41fcf9fbeb23d91b1cb3cbcb23f8dfcb7ccf9eb35794ce8c1b83f1cb1b9624b387d2c7d1578bd9d2 }


condition:
	$a0
}