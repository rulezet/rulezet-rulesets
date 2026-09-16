rule Win_Trojan_Timid_2
{
strings:
	$a0 = { b41aba2aff832efcff09cd21e830007503e88100b41ab480cd218b1efcff8b874300a300018b874500a302018a }


condition:
	$a0
}