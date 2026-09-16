rule Win_Trojan_Dumb_1
{
strings:
	$a0 = { bf00015781ed87018db64002a5a48d964602e8d8ffb44e8d9687012bc9888e700280be70020377c2cd2172beb8023d }


condition:
	$a0
}