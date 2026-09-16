rule Win_Trojan_Trivial_173
{
strings:
	$a0 = { 2e2a00919692b44ecd2192b29eb8023dcd219399b442cd21b440b122b601cd21c3 }


condition:
	$a0
}