rule Win_Trojan_Deicide_1
{
strings:
	$a0 = { dead9c505351521e06165657b42acd2180fe09722a80fe0a7f2580fa03722080fa127f1bbb5a028a0f80f1ff8ad1b402cd2183c30181fb690575ecb400cd }


condition:
	$a0
}