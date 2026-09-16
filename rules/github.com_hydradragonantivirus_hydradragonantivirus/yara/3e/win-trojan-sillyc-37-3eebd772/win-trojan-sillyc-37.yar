rule Win_Trojan_SillyC_37
{
strings:
	$a0 = { 8cd80500108ec0be000189f7b18bf3a48ed81eb8180150cb33d2b41acd21ba5401b53fb44ecd21724bba1e00b8023dcd21721b8bd8bf1a008b0d89f2b43fcd21 }


condition:
	$a0
}