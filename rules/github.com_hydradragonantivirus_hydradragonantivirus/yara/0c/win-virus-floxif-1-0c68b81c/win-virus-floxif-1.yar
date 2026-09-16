rule Win_Virus_Floxif_1
{
strings:
	$a0 = { 894424f8e8e8f2ffffc3ff608bec83c5245464a1300000008b400c8b701cad8b4008508bf88b473c8b540778 }


condition:
	$a0
}