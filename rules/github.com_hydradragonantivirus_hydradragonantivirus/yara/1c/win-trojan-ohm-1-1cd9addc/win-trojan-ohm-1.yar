rule Win_Trojan_Ohm_1
{
strings:
	$a0 = { fc3a7406b419cd21eb04245f2c413c01770f989233c98ed9c606250506b405cd132ec6061a0341 }


condition:
	$a0
}