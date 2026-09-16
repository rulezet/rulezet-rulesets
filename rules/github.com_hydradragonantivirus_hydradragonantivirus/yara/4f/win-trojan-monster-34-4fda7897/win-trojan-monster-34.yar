rule Win_Trojan_Monster_34
{
strings:
	$a0 = { 02bede2cfc300446e2fb25cdcd934e23ce2509cc51954d01cc9d503626330b89de332541cc464984cf6ecdcc }


condition:
	$a0
}