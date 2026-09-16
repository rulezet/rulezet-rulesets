rule Win_Trojan_SatanBug_5
{
strings:
	$a0 = { 2ef826f52645454a264a4a4345b965004a4a4d434d424b4b2ef92ef92e904a45454a4afcf52e432ee800002e2e5f }


condition:
	$a0
}