rule Win_Trojan_VGEN_423
{
strings:
	$a0 = { 2a11bae0000500003b060200722ab409ba1c01cd21b8014ccd21240043cfda14420f3dd25fcd21909cd100242020 }


condition:
	$a0
}