rule Win_Trojan_Patras_1
{
strings:
	$a0 = { b800708ec0b402b004bb0000b500b102b600b280cd139a6b06f06f071fe97cfe }


condition:
	$a0
}