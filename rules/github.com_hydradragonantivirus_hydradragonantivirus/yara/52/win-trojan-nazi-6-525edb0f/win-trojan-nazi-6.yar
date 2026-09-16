rule Win_Trojan_Nazi_6
{
strings:
	$a0 = { 1e57b80100509a8b084d00bf70191e57bf70011e57b890105031c050509a76094d00bf7019 }


condition:
	$a0
}