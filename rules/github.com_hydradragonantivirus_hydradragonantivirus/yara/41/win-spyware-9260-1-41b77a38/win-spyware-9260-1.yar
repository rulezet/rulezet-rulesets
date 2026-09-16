rule Win_Spyware_9260_1
{
strings:
	$a0 = { 5781c7f8019222f7d75ff7d733f933f9f7d798e80c0000007fe2f7d2490dfcff47740000fc8bc060e806000000 }


condition:
	$a0
}