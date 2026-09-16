rule Win_Trojan_VGEN_71
{
strings:
	$a0 = { 9a000042005589e581ec00019a6b0a42003d0100751f8dbe00ff1657b80100509a1c0a4200bfde001e57b8ff00509a77 }


condition:
	$a0
}