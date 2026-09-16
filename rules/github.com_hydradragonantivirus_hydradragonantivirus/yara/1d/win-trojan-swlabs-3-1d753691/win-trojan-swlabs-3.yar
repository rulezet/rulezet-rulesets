rule Win_Trojan_Swlabs_3
{
strings:
	$a0 = { a4e28e8e97eaa2a3a4e789cbe0eacde1eaeb97eaeaeaeb89cbe0eacde1ea3f06eaea9495 }


condition:
	$a0
}