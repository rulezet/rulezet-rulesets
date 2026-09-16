rule Win_Trojan_Elite_5
{
strings:
	$a0 = { 0400baf8ffb43fcd218b46e905b501720e807efce97506807eff567402f8c38b5efab43ecd21f9 }


condition:
	$a0
}