rule Win_Trojan_SillyOR_6
{
strings:
	$a0 = { 8ec00e1f33ffb145f3a48ed8ba4000b8ff25cd21ba1f00b021cdffc380fc3e751c1e52515033c933d2b80042cd }


condition:
	$a0
}