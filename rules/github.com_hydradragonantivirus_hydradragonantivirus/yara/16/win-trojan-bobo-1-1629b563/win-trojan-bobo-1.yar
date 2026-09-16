rule Win_Trojan_Bobo_1
{
strings:
	$a0 = { 5d81ed0a008bfd9081c72300b92805908a860600300547e2fbbf00018bf5a4a4a4b8ab4bcd213db0b075170e1f }


condition:
	$a0
}