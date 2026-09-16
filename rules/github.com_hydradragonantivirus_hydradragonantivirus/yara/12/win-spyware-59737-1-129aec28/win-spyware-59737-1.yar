rule Win_Spyware_59737_1
{
strings:
	$a0 = { 558bec83ec24535657c745fc0100000068d2e6 }


condition:
	$a0
}