rule Win_Trojan_Redir_7
{
strings:
	$a0 = { 6a606810444100e85fedffffbf940000008b }

	$a1 = { 41006e0074006900760069007200750073 }


condition:
	$a0 and $a1
}