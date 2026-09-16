rule Win_Trojan_Ceel_2
{
strings:
	$a0 = { 33c004ff480bc075fb7401f4609ce8000000005d }


condition:
	$a0
}