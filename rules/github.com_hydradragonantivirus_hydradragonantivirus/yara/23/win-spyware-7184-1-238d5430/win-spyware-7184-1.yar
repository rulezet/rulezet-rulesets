rule Win_Spyware_7184_1
{
strings:
	$a0 = { 605281c2d0273f423334245a5633fe5f61e80c0000006d5a02f7404b }


condition:
	$a0
}