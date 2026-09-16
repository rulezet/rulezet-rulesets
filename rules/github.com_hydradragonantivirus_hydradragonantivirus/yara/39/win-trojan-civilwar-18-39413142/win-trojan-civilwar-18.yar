rule Win_Trojan_CivilWar_18
{
strings:
	$a0 = { 81ed0901bf00018db6ff02b90600f3a4b4a0cd213d010074598cc8488ed8803e00005a7547a103002d4000a303008b }


condition:
	$a0
}