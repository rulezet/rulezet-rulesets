rule Win_Trojan_HMABOO_1
{
strings:
	$a0 = { b0d1e664e464240275fab0e3e66061bb007c0efc1fc4774cb9fe018d3c0e5356f3a45eb1fff3a5 }


condition:
	$a0
}