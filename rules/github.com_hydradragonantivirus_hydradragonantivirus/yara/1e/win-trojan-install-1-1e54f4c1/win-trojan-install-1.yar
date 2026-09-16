rule Win_Trojan_Install_1
{
strings:
	$a0 = { 46051e57bf8a051e57bf94051e579a9900c000bf46051e57bfca021e57b8ff00509abe07d7008d }


condition:
	$a0
}