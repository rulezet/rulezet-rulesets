rule Win_Spyware_5759_1
{
strings:
	$a0 = { 8b45e8ba68504000e8adebffff75498d55e433c0e8f9f5ffff8b45e4ba80504000e894ebffff }


condition:
	$a0
}