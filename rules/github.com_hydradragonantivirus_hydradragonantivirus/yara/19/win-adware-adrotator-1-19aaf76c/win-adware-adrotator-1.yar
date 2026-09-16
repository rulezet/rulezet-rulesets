rule Win_Adware_AdRotator_1
{
strings:
	$a0 = { 3f41564342616e6e6572526f7461746f724040 }


condition:
	$a0
}