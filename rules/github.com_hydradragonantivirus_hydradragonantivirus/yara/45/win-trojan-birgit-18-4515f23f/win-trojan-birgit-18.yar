rule Win_Trojan_Birgit_18
{
strings:
	$a0 = { e2fdbaf101ffd2c353bad901ffd25bb440b9f100ba0001cd2153bad901ffd25bc3 }


condition:
	$a0
}