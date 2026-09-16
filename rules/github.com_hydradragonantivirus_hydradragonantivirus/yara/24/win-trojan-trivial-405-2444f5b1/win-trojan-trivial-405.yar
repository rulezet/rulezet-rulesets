rule Win_Trojan_Trivial_405
{
strings:
	$a0 = { 27ba3201cd21b44fcd217222b42fcd21061f8bd383c21eb8023dcd218bd8b440b93c00ba0001cd21b43ecd21 }


condition:
	$a0
}