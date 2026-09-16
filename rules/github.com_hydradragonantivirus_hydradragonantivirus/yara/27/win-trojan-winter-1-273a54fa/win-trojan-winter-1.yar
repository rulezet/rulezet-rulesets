rule Win_Trojan_Winter_1
{
strings:
	$a0 = { 0d00b440b91c04ba0000cce81800c3becc03b9b8038a1480ea0280f2f9c0ca0488144ee2f0c38d }


condition:
	$a0
}