rule Win_Trojan_Skid_2
{
strings:
	$a0 = { 6074095558b4039cff9cb0018d7f5026817d02b40d750d268b0526890733c0b9b001 }


condition:
	$a0
}