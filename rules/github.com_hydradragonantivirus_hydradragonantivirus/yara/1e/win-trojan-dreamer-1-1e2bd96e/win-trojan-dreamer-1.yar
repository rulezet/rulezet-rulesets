rule Win_Trojan_Dreamer_1
{
strings:
	$a0 = { 81ed0301b8ce42cd217364b82135cd21fa3e899ef4013e8c86f601fbb01ccd21fa3e899ec5033e8c86c703fbe86c }


condition:
	$a0
}