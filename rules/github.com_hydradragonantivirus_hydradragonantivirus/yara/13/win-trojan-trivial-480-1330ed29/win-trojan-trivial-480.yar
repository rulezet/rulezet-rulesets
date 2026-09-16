rule Win_Trojan_Trivial_480
{
strings:
	$a0 = { eb0159c606d2010090b441baa101cd21b44eb90700ba9b01cd217277e86400b43fb90700bad301cd21e85200 }


condition:
	$a0
}