rule Win_Spyware_1760_1
{
strings:
	$a0 = { 8d4dccbab4491413a194661413e8ecf1ffff8b55ccb894661413e89fe8ffff8d55c8b823000000e8e6f9ffff8b45c8e866eaffffe819faffffb894661413e8a7eaffffe812f3ffff33c05a5959648910680c491413 }


condition:
	$a0
}