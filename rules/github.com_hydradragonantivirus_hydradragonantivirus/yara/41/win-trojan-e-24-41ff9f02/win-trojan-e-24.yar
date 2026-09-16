rule Win_Trojan_E_24
{
strings:
	$a0 = { 79f7c17a2d01bf056d902ce50860932e285c0fc0b628db8c1b55cdb3b47acb174dc84dc335baf6c512d8fc46408945 }


condition:
	$a0
}