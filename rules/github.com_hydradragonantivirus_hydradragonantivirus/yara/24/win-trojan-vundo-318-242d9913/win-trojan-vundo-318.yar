rule Win_Trojan_Vundo_318
{
strings:
	$a0 = { eb23381176eb2e77e44d021350494e6f7c055a8b6881266714bdb20380b9fe5fac750a7b98ebdef1d657442d62f3eb2c }


condition:
	$a0
}