rule Win_Trojan_RiftVilly_3
{
strings:
	$a0 = { 0301cd21c3b440cd2172e2c3b44231c9cd2172d9c3b43fcd21c3bf00018d760ab90600f3a4 }


condition:
	$a0
}