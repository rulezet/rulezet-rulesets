rule Win_Trojan_BewareBug_4
{
strings:
	$a0 = { 54fec4bb7544feccb96b6141cd214b81fb7347750c33c04181f9224d7503e994058cc1b8203540 }


condition:
	$a0
}