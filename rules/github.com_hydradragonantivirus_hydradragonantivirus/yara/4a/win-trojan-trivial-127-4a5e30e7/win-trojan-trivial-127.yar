rule Win_Trojan_Trivial_127
{
strings:
	$a0 = { 2e2a00ba000152b120b44ecd21ba9e00b8023dcd21935ab440cd21c3 }


condition:
	$a0
}