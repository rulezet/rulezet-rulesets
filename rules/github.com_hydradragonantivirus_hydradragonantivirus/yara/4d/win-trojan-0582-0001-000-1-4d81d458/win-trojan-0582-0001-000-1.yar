rule Win_Trojan__0582_0001_000_1
{
strings:
	$a0 = { 3dba1e05cd218bd8b440ba0001b90902cd21b43ecd21b42bb94356ba4d4fcd213c00bacc0275 }


condition:
	$a0
}