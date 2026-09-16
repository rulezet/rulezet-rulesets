rule Win_Trojan_Trojan_211
{
strings:
	$a0 = { 18139ddb9ee868251e13c317f7c1f911701ae171cb57e438892acf1759b04ae0e438a4ad241bd01b }


condition:
	$a0
}