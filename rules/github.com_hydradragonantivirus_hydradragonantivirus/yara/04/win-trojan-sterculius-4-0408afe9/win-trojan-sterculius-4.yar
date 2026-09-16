rule Win_Trojan_Sterculius_4
{
strings:
	$a0 = { ee03061e0e0e071f8bee83bc7e0000750cfc8db4ac01bf0001a5a58bf533c08ec0bfe00126817d035354741ab9b0 }


condition:
	$a0
}