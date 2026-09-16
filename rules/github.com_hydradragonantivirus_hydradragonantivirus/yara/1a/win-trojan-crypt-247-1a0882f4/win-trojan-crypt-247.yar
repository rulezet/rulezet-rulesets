rule Win_Trojan_Crypt_247
{
strings:
	$a0 = { 6a1868f0100001e80801a630bf940000008bc7e80801a67c8965e88bf489 }


condition:
	$a0
}