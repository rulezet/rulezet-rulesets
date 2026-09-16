rule Win_Trojan_Immortal_3
{
strings:
	$a0 = { 08ffffb440b9890899e852013bc87519b8004233c999e84501b440b91c00ba8908e83a0180 }


condition:
	$a0
}