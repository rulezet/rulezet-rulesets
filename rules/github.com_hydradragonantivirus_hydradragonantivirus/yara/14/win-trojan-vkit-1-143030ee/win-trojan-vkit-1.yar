rule Win_Trojan_VKit_1
{
strings:
	$a0 = { 2e812c632e4646e2f74b2f6386904064b94b4d693c823c6abb213e65bb194665d307d407d429b5453264e27dbbf9e566fb }


condition:
	$a0
}