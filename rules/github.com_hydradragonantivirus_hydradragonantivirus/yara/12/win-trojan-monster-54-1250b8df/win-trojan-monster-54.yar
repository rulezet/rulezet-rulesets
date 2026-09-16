rule Win_Trojan_Monster_54
{
strings:
	$a0 = { 8b4417a300018a4419a20201b82425baf60103d6cd21 }


condition:
	$a0
}