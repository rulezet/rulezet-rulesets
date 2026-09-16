rule Win_Spyware_3915_1
{
strings:
	$a0 = { 558bece8500000008b15b06140008b12b8cc514000e876eeffff5dc21000 }


condition:
	$a0
}