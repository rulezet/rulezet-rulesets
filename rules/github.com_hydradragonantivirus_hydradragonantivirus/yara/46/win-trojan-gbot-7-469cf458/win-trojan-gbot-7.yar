rule Win_Trojan_Gbot_7
{
strings:
	$a0 = { 55fc8bec81c4a0fbffff68003000006aff506affe84700000083e80303d10fafc2678d160600b9ff00000023c184c074 }


condition:
	$a0
}