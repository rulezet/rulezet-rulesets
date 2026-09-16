rule Win_Trojan_Virogen_9
{
strings:
	$a0 = { 8beffabfb0018bff75007400750074008bf67f008bea7f008bef74000bed7200740072007f008bff8bee8bef8bee }


condition:
	$a0
}