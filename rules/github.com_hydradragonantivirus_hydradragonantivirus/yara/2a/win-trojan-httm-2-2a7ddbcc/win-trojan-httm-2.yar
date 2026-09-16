rule Win_Trojan_HtTM_2
{
strings:
	$a0 = { dd81fc5d81ed06012e89a6f203fa8cc88da66c048ed0fb602e83bef203fe750a8db6e401bf }


condition:
	$a0
}