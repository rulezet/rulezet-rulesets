rule Win_Trojan_Gen_245
{
strings:
	$a0 = { c406eb2ab87a0350e8b1fe590bc07516833e7803007c0f7f08813e760324137605b87a03eb18b8 }


condition:
	$a0
}