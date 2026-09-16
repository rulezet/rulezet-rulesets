rule Win_Spyware_Banker_1355
{
strings:
	$a0 = { dfd2096f8ed98e9c04de2ca63dd4098c55dbff997657f9fc774faf4c6aa9eb7ea4ac2f62ddca3a8a6ec1673030ed99cf178c91bc068855a210e69ecadedd6b15961929b0 }


condition:
	$a0
}