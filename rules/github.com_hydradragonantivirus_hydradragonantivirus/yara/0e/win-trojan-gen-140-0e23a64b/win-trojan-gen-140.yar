rule Win_Trojan_Gen_140
{
strings:
	$a0 = { cb005589e5b800029a3005cb0081ec0002b80000ba0000a3400089164200e8e7fec606f9ec01eb04fe06f9ec8d }


condition:
	$a0
}