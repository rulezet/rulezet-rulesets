rule Win_Trojan_Unkm_9
{
strings:
	$a0 = { b90000ba0000cd21b8004083c1038d960104cd21b80242b90000ba0000cd21e830feb8005704018b }


condition:
	$a0
}