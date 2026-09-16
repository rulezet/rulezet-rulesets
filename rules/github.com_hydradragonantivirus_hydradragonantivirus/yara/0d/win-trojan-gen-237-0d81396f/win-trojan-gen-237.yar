rule Win_Trojan_Gen_237
{
strings:
	$a0 = { 20d024e8ed4bad069cfde19cfd0300e84f5ef22de8ec33ecfd3d4df37ac1f015c4f4b4a2d94f }


condition:
	$a0
}