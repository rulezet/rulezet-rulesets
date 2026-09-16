rule Win_Trojan_DownLoader_1
{
strings:
	$a0 = { e0522456cf6daea1bb00b488d2666bc193e9fb430f3c735896be7f65a16e55d60a42c3f39271c51e983f583f68490670583b9291a1a0120822192eed5ae3aece }


condition:
	$a0
}