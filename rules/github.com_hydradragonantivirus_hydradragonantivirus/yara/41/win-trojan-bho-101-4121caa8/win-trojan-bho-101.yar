rule Win_Trojan_BHO_101
{
strings:
	$a0 = { 433a5c[0-1]7a69702e706c7567696e[0-2]557365724964 }

	$a1 = { 7961686f6f }

	$a2 = { 50257354502f312e310a486f73743a }


condition:
	$a0 and $a1 and $a2
}