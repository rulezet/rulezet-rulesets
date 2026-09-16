rule Win_Trojan_Delf_2227
{
strings:
	$a0 = { 5568194d400064ff30648920ba304d40008d8520feffffe8abdcffff }

	$a1 = { 776d766473662e6178 }


condition:
	$a0 and $a1
}