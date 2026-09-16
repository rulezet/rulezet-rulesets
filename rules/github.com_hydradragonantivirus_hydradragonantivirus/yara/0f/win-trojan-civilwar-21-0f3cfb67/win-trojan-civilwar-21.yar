rule Win_Trojan_CivilWar_21
{
strings:
	$a0 = { 5d81ed0901bf00018db66d03b90600f3a4b4a0cd213d010074778cc8488ed8803e00005a7563a103002d5000a3 }


condition:
	$a0
}