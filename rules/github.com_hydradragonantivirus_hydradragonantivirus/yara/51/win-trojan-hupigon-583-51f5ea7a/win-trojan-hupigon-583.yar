rule Win_Trojan_Hupigon_583
{
strings:
	$a0 = { 558bec807d0801750b66b88200e8e6feffffeb0966b89001e8dbfeffff5dc20400 }


condition:
	$a0
}