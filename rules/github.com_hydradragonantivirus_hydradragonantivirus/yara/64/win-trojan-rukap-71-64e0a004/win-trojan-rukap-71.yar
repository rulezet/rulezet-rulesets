rule Win_Trojan_Rukap_71
{
strings:
	$a0 = { 1ec116d51a2d5d53e20837cf4e7ae0ebf7c53ab96950c7a137ae2b93ff89ca1f6b0e7abb6e352cbe16802806081fd6eb6792c8e8762253a275baaf34e676d01863 }


condition:
	$a0
}