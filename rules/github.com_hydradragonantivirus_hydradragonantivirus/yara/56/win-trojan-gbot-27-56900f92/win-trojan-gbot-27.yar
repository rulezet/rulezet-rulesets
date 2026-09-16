rule Win_Trojan_Gbot_27
{
strings:
	$a0 = { 55fc8bec81c4a0fbffff6a006a006aff6a006a02e851000000fc83e8044003d10fafc2906a06f95a25ff000000663dac000f84800000006a00 }


condition:
	$a0
}