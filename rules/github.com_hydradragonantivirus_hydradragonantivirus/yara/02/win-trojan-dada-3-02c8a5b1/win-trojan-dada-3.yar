rule Win_Trojan_DaDa_3
{
strings:
	$a0 = { 8b5efe8d164c06b90200cd21baff }


condition:
	$a0
}