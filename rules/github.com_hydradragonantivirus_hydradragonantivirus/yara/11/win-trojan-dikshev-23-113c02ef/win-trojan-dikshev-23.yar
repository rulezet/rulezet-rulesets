rule Win_Trojan_Dikshev_23
{
strings:
	$a0 = { 2abf9e0091b44e8bd6cd2173039090c38bd7b82e5bae75fd66c705636f6d20cd2172ec93b440b12f }


condition:
	$a0
}