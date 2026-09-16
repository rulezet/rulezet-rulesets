rule Win_Trojan_IRCBot_207
{
strings:
	$a0 = { eb08ad294c7e94955304d4e89ce6b008f165cc2f20c76ee3e00d8789186040199e5c31b8f7413d4db73ecb78532dab9527507dbaa270b6f743e2b6a37fb4bacad2cc5fcea766d13cf22e01e8500e }


condition:
	$a0
}