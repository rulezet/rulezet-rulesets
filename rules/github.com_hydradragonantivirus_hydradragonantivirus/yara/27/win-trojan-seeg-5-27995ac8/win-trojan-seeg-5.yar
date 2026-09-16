rule Win_Trojan_Seeg_5
{
strings:
	$a0 = { 73282cda354bd20134a127ac40bafa6c295cd4d4442c2ccfab3f0b2a4126f951412a750a9f76d72a }


condition:
	$a0
}