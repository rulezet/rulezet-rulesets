rule Win_Trojan_O_3
{
strings:
	$a0 = { bf920a57b9920a8b160103b00ee87a015ab440cd21e80d00b91800ba0303b440cd21e952ff }


condition:
	$a0
}