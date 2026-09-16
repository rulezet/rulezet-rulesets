rule Win_Trojan_QQShou_12
{
strings:
	$a0 = { ae7fdf928120d194a0cab4c672abb7d2e27c33fe23e618dfc129820c0e78ec20628c292350c78e1f534c53aceb102b037d66ec6ddf10bd1eeb84ad0787e8 }


condition:
	$a0
}