rule Win_Trojan_SdBot_62
{
strings:
	$a0 = { e4ce725fd871a4726ddbe489633bd49889bd80304156454e53487549244c44ecd1522ecd40bb66a4783e }


condition:
	$a0
}