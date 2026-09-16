rule Win_Trojan_Kufu_1
{
strings:
	$a0 = { b82135cd218c06????891e????b425ba????cd21ba0302cd273d0ff075 }


condition:
	$a0
}