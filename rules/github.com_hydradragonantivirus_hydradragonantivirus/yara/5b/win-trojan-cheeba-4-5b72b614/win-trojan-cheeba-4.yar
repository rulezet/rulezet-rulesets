rule Win_Trojan_Cheeba_4
{
strings:
	$a0 = { bf0001902e8035014781ff700772f5 }


condition:
	$a0
}