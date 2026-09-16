rule Win_Trojan_Keypress_4
{
strings:
	$a0 = { 027405c7070200f9f51fc3f606180101740d8cc0051000 }


condition:
	$a0
}