rule Win_Spyware_8056_1
{
strings:
	$a0 = { 578d3a81f7bc42f45687d75f81f25468920481f25468920481f2bc42f456e84b }


condition:
	$a0
}