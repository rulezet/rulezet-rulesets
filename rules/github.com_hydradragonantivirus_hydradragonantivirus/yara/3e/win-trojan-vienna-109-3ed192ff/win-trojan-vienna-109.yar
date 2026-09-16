rule Win_Trojan_Vienna_109
{
strings:
	$a0 = { fc8db70900b90300bf0001f3a489dfb430cd213c037303e9700106b42fcd218c4502891d078d956400b41acd }


condition:
	$a0
}