rule Win_Trojan_Miras_1
{
strings:
	$a0 = { 2acd2133db8b9f010181c37f038b078b5f023ada760680c21e80ee012ad380fa0a731b3afe72173bc27213bf0001be }


condition:
	$a0
}