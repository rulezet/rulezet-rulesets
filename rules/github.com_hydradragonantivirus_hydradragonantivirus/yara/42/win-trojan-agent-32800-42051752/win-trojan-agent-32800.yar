rule Win_Trojan_Agent_32800
{
strings:
	$a0 = { b9767a1e7c708956cdde50503c57aafc6b33eb8a0d69ac4d0eec55d6dc754a0864216a65a0b1b5dce70ec899e6c2915658895f41b9fc91e2641afd3f703496f831 }


condition:
	$a0
}