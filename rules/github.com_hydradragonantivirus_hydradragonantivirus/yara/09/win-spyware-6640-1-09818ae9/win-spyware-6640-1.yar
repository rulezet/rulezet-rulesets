rule Win_Spyware_6640_1
{
strings:
	$a0 = { 33f6b880204100bbaa214100fe00403bc375f94681fec13c030075e633f6cf }


condition:
	$a0
}