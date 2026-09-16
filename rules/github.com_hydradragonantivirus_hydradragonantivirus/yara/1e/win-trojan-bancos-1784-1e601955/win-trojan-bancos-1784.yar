rule Win_Trojan_Bancos_1784
{
strings:
	$a0 = { 2506beb0b701663e97a2b7375a57cd81ac9721ebd7eecd742eb3139d15bf6b85ed452ffccbeaa6d832066347e20a9cd001de3eb424317d6f10509d90629bb7fecf076bbe185b }


condition:
	$a0
}