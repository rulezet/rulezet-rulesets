rule Win_Spyware_4770_1
{
strings:
	$a0 = { 535083c40456538bde5b538b }


condition:
	$a0
}