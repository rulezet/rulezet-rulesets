rule Win_Trojan_Remor_4
{
strings:
	$a0 = { 02a3e702a1e902a30c038a261c038b16e70203160c0381c20001cd2183c21e89160e0389 }


condition:
	$a0
}