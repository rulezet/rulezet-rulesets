rule Win_Trojan_VGEN_656
{
strings:
	$a0 = { 90e800005e81c6c200bf0001fca5a581eec900b44ebabf0003d6cd217259b8023dba9e00cd21724f93b43fb904 }


condition:
	$a0
}