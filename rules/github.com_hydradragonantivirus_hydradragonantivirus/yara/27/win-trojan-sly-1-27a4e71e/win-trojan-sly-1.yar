rule Win_Trojan_SLY_1
{
strings:
	$a0 = { 7cbb020333c08ec0fa8ed08be6fb8ed8ff8f11018b871101c1e0068ec0b800029180fa807403 }


condition:
	$a0
}