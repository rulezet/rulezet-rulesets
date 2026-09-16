rule Win_Spyware_Banker_1405
{
strings:
	$a0 = { ba4c9b50bfc3bb3400681301b93bd341b98b34f95c84d197d32fba7ec92c0a9816a296bf667b3c74e410a208b875f9fd3a71806346f791fd56b4f71080c2f60fedd0a456 }


condition:
	$a0
}