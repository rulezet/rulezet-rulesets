rule Win_Trojan_Midi_1
{
strings:
	$a0 = { 83ee0e56b88818cd213d494d7443b44abbffffcd21b44a }


condition:
	$a0
}