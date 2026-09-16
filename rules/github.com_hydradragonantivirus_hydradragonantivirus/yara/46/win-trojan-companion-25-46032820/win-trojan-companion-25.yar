rule Win_Trojan_Companion_25
{
strings:
	$a0 = { cd21891e55018c065701ba1801b425cd21b28acd2780fc4b753760061ebf5900578bf20e07acaa0ac075fab456 }


condition:
	$a0
}