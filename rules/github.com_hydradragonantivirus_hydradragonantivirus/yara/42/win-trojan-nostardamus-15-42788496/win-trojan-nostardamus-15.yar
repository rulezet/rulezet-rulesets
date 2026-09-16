rule Win_Trojan_Nostardamus_15
{
strings:
	$a0 = { 7503b04bcf80fc5b750ce8ad0372042ea30e00ca02 }


condition:
	$a0
}