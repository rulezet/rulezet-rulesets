rule Win_Trojan_QQShou_16
{
strings:
	$a0 = { 3142408b2689f67f8cd8bafdc4fb10c462c1eb3fd75283edbc0d9f5583ccf4c9ebeccabf517038413a3265fdc02789fd970938faace008525dd16a441d3f }


condition:
	$a0
}