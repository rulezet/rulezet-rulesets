rule Win_Trojan_Bancos_720
{
strings:
	$a0 = { bbf68879f9500095aead74f8007c7fe68dddc5cadcd423ce2b88489d405b3a65cc3e5c06af09f525b75e6bcfe35b8fcf8cf916f3926922d41b424875a244be801ca12a01a6e582d89b570eeb5f7d1bad }


condition:
	$a0
}