rule Win_Spyware_7342_1
{
strings:
	$a0 = { 81c7c47260355481efc4726035893c24d3cf }


condition:
	$a0
}