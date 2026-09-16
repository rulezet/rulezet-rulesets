rule ARIA_encryption_KRK__32_lil_48_
{
strings:
	$a0 = { b7c17c51940a2227e8ab13fee06e9afacc4ab16d20c8219ed5b128ffb0e25def1d3792db70e92621759724030ec9e804 }

condition:
	$a0
}