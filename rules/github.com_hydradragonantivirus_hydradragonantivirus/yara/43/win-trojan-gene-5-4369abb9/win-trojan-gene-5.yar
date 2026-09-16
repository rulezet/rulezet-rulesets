rule Win_Trojan_Gene_5
{
strings:
	$a0 = { 217252b8023dba9e00cd2193b80057cd215152b440ba0001b90b00cd21fe06b7047504fe06b704 }


condition:
	$a0
}