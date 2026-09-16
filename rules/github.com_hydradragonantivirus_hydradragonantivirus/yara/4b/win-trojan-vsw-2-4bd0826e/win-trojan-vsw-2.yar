rule Win_Trojan_VsW_2
{
strings:
	$a0 = { 95005589e5b800029acd02950081ec000231c0a3420be92f01208fe0aee8e320afe0aee9a5ada8ef20e320a0a2 }


condition:
	$a0
}