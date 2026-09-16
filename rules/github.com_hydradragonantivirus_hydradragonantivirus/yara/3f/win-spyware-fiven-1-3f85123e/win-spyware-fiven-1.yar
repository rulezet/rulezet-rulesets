rule Win_Spyware_Fiven_1
{
strings:
	$a0 = { cec545bed2a410acb7d815bed65c83fc8b38a8871aa514637944ed3a0b8eb78171d59957c5074f0170e008a8ba6910178bd0 }


condition:
	$a0
}