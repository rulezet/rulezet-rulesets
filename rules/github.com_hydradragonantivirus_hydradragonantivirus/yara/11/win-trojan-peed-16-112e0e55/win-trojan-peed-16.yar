rule Win_Trojan_Peed_16
{
strings:
	$a0 = { c1e910c1e91081e910????006800050000f7d98b09ffd152682a335f04e8 }


condition:
	$a0
}