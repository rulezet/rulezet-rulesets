rule Win_Trojan_Gokar_1
{
strings:
	$a0 = { 47006f0062006f00 }

	$a1 = { 7400650061006d00760069007200750073 }

	$a2 = { 4b006100720065006e }


condition:
	$a0 and $a1 and $a2
}