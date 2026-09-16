rule Win_Trojan_LogonInvader_1
{
strings:
	$a0 = { 5374617475737c4b6579204c6f6767657220456e61626c6564 }


condition:
	$a0
}