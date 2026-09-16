rule Win_Trojan_WildThing_3
{
strings:
	$a0 = { 5d9081ed060190e8070292a9c11da01f1e48babb9289951cf7251eab33d23e9fe11f6be897a9311cab58ad1f92 }


condition:
	$a0
}