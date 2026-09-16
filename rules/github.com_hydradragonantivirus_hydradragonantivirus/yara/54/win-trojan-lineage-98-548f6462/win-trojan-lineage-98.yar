rule Win_Trojan_Lineage_98
{
strings:
	$a0 = { 5dc36815f14c571aec59b9a38a904c276b032d10aed2cf034788c8fb0819daeaf960743c8b6d860078b4f33fde4b425ce46aa96f804c5f92703611111c3cefa7a0fde859 }


condition:
	$a0
}