rule Win_Dropper_VB_382
{
strings:
	$a0 = { 8b8dd4fbffff5168e8334000ff15401040008bd08d8dccfbffffff1560114000508b95d0fbffff52ff1540104000 }


condition:
	$a0
}