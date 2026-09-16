rule Win_Trojan_Tiny_84
{
strings:
	$a0 = { 5e83ee0350b4e9cd21bf000633c98ec1b1fff3a406b8210650cb90909090bf8400b102b85706fc26ff35268f85 }


condition:
	$a0
}