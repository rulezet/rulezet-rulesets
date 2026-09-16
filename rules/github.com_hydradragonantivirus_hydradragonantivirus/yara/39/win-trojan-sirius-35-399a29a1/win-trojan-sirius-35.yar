rule Win_Trojan_Sirius_35
{
strings:
	$a0 = { 3a98068dea8d216802ce271f44380ea62bef2908fad63dd738d8888cdc810c9a }


condition:
	$a0
}