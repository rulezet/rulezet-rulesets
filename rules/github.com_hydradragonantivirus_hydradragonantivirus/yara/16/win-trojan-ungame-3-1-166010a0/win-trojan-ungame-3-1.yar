rule Win_Trojan_Ungame_3_1
{
strings:
	$a0 = { b8f1ffcd213d33567471b82135cd2131c08ed82e891e60012e8c066201b80935cd212e891e67022e8c066902ff0e }


condition:
	$a0
}