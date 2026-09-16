rule Win_Trojan_HackMaster_1
{
strings:
	$a0 = { e800005d83ed051e060e1f8db624008d96aa048b043e3386aa04890446463bf272f1 }


condition:
	$a0
}