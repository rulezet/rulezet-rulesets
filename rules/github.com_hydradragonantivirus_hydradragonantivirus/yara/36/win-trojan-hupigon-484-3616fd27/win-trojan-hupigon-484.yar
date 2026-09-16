rule Win_Trojan_Hupigon_484
{
strings:
	$a0 = { 7a412e22a5297fc11ed912d56c83beb208beaeeca71b014bb7dde20de9db1bfa169f140af09ad2b72b6a5c50c82e33b4dc0e2c26cc23208fdf17b0baef4ed38857eaaf378c57509908afe1ae746d }


condition:
	$a0
}