rule Win_Trojan_AOD_2
{
strings:
	$a0 = { 2d03008986ed00e80801b8004233c933d2cd21b440b906008d96ec00cd21e82e00e8260073a4e8 }


condition:
	$a0
}