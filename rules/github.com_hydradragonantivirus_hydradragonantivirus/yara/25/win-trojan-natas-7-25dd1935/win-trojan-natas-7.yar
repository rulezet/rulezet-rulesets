rule Win_Trojan_Natas_7
{
strings:
	$a0 = { f881d7b8a38d0eed0846f9f583defff811bcfeff23c9e102ebef }


condition:
	$a0
}