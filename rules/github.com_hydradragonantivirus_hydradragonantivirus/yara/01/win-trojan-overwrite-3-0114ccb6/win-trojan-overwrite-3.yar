rule Win_Trojan_Overwrite_3
{
strings:
	$a0 = { 1e57bff4011e57b8c00f5031c050509ad0092c009a46022c00bf70001e579a5f09 }


condition:
	$a0
}