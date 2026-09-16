rule Win_Trojan_Neko_3
{
strings:
	$a0 = { f71e2f01f6160100800e170325f71e1200f71e8703ff0e8600c2 }


condition:
	$a0
}