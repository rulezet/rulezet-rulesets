rule Win_Trojan_W_171
{
strings:
	$a0 = { b43eff17ebdc33c98bd6b43fe83d0000008b4e3c8d040e80385075d58b482881f90004000072ca55034834894d1d8bf8 }


condition:
	$a0
}