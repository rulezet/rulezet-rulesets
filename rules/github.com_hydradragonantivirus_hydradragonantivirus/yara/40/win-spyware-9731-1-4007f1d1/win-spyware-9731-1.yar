rule Win_Spyware_9731_1
{
strings:
	$a0 = { 4023c0e8900500005dc3670199395e81 }


condition:
	$a0
}