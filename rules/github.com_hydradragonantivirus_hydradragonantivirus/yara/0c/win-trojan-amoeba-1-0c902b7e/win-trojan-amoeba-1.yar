rule Win_Trojan_Amoeba_1
{
strings:
	$a0 = { 1c25cd21b82135cd218bd38d1e2f }


condition:
	$a0
}