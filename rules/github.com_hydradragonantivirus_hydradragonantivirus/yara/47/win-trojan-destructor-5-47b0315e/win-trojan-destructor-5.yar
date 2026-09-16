rule Win_Trojan_Destructor_5
{
strings:
	$a0 = { 40b902008d963b02cd21e88c002efe0e3a027506b43ecd21eb08b43ecd21b44feb93b480b41acd }


condition:
	$a0
}