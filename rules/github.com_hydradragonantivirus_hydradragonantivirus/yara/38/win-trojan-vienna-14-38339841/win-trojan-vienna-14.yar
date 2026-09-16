rule Win_Trojan_Vienna_14
{
strings:
	$a0 = { 40b98d5c89f281ea3202cd21721e3d8d5c7519b80042b9 }


condition:
	$a0
}