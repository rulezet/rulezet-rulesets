rule Win_Trojan_Invader_2
{
strings:
	$a0 = { 58011e57bf62041e57b84f1d5031c050509ac307a901bfd8011e57bf62041e57b84f1d5031c050 }


condition:
	$a0
}