rule Win_Trojan_Vienna_108
{
strings:
	$a0 = { 16fc8db70900b90300bf0001f3a489dfb430cd213c037303e95101b42fcd218c45021e07891d8d951100b41acd }


condition:
	$a0
}