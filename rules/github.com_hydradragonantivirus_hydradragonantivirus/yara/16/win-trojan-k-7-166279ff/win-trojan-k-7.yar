rule Win_Trojan_K_7
{
strings:
	$a0 = { cd21f7e22d0f0050a10d0133d2f7f150b419cd21bb000159415acd269de819ffbe29038bfeac }


condition:
	$a0
}