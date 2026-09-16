rule Win_Trojan_WinStart_2
{
strings:
	$a0 = { 3dfefe75073bc37503be94193d00437512538bda813f2f575b75089df9b802 }


condition:
	$a0
}