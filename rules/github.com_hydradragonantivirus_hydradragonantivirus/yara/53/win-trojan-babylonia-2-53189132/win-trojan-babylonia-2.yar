rule Win_Trojan_Babylonia_2
{
strings:
	$a0 = { 618b450c6689460266c7460400ece8d70000008ed88ec087f7a5a58bfd8b5f020fb70fe8b9 }


condition:
	$a0
}