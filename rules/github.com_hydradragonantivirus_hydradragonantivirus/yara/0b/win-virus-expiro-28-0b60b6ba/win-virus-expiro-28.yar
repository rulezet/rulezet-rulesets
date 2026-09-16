rule Win_Virus_Expiro_28
{
strings:
	$a0 = { 50519052905390545556575589e583ec??c745????000000b8??000000b9??000000 }


condition:
	$a0
}