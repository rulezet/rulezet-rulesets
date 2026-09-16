rule Win_Trojan_Scitzo_1
{
strings:
	$a0 = { da2106e2fb908cc88ed8be3204b000b848028bc88bc18bc88134030c4646e2f84b43eb3b90eb1e03b843b58d08 }


condition:
	$a0
}