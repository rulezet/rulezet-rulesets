rule Win_Trojan_Unspeed_1
{
strings:
	$a0 = { 50b8070450cbb82135cd21891e11018c06130180ec10baee02cd21b80835cd21891ed6038c }


condition:
	$a0
}