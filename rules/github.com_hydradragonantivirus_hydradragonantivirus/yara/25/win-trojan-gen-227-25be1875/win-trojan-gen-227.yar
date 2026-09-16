rule Win_Trojan_Gen_227
{
strings:
	$a0 = { 33081e579afb048000fe0683305dc20200052a2e4558455589e5bf91040e57b8200050bf84301e }


condition:
	$a0
}