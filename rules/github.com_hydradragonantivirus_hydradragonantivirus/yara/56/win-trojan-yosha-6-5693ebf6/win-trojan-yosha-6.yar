rule Win_Trojan_Yosha_6
{
strings:
	$a0 = { b98f03b42fcd21b80200f7e301c68034b846e2fa }


condition:
	$a0
}