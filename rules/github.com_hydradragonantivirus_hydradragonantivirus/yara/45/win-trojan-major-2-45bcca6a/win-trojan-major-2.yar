rule Win_Trojan_Major_2
{
strings:
	$a0 = { f2121969fba21a589114411b910c471b9bd8c61a99cb1ad73bdc1c231b1bae5aa31b1aa0231bd73b }


condition:
	$a0
}