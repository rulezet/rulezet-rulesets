rule Win_Trojan_One13_1
{
strings:
	$a0 = { 8bd081c20001b00fe800005ab440cd21e8c600582d0300a30603ba0503b90400b440cd215a }


condition:
	$a0
}