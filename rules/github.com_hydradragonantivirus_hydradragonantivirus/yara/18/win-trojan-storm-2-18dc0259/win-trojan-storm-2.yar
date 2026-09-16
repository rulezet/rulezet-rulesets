rule Win_Trojan_Storm_2
{
strings:
	$a0 = { 05899dae0557bec20203f78bfbb91400f3a65f740bb8fe4bcd2181fd3412 }


condition:
	$a0
}