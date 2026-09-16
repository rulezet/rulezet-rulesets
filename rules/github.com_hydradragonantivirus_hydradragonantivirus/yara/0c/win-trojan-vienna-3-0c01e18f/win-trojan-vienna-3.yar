rule Win_Trojan_Vienna_3
{
strings:
	$a0 = { 50ba????8bf283c60090bf0001b90300fcf3a48bfab430cd213c02 }


condition:
	$a0
}