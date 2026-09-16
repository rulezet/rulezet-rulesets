rule Win_Trojan_Tyst_1
{
strings:
	$a0 = { 3e7202007403e99100833e700205760731c09ae9003300bf44001e579a3e001700bf7001 }


condition:
	$a0
}