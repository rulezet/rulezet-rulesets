rule Win_Trojan_Wildy_6
{
strings:
	$a0 = { cd213c05752eb409ba4702cd21e81f003c6c75f9e81100e815003c7375f9e80700e80b003c6475f98ad0b402cd21 }


condition:
	$a0
}