rule Win_Trojan_NPox_5
{
strings:
	$a0 = { 2ea3a5072ec606a407e9baa407b90300b440e806022e8b169e072e8b0ea007b80157e8f601 }


condition:
	$a0
}