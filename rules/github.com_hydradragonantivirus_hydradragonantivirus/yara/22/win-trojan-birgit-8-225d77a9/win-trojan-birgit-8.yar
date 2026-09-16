rule Win_Trojan_Birgit_8
{
strings:
	$a0 = { 53b440b9e7038d960901cd215b53b801573e8b8e02033e8b960403cd215bb43ecd2168014358ba }


condition:
	$a0
}