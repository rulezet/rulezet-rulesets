rule Win_Trojan_MF_8
{
strings:
	$a0 = { 52031e57b87a17509a7d068c00bf52031e57bfd2031e57b801005031c050509a68078c00bf5203 }


condition:
	$a0
}