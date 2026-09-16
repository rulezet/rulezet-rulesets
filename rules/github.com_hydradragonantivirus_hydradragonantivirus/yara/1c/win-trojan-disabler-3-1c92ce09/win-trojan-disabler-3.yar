rule Win_Trojan_Disabler_3
{
strings:
	$a0 = { 683472400051ffd68b54241052ffd38d44241050683f000f006a0068f87140006801000080ffd7 }


condition:
	$a0
}