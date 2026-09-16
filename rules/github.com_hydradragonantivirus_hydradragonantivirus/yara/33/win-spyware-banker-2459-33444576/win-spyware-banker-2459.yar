rule Win_Spyware_Banker_2459
{
strings:
	$a0 = { c02c10236a7a9647de9f7eb9dbf7cad70be47198fb5e33df8d6fa18be977374daab0be4471817bf04cc3e734876a228af99edb5ac95a92460fca81537fc4113f8ffb60e276ed84558401 }


condition:
	$a0
}