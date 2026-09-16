rule Win_Trojan_Simbiot_2
{
strings:
	$a0 = { 6f032ec6064703e92d03002ea34803b8004233c933d2e888fe0e1fb440b91a00ba4703e87bfe }


condition:
	$a0
}