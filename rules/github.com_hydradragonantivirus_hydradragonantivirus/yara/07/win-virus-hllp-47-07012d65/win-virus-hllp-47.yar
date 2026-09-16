rule Win_Virus_HLLP_47
{
strings:
	$a0 = { c20400077a5371412e74685589e5b844019a??????0081ec4401 }


condition:
	$a0
}