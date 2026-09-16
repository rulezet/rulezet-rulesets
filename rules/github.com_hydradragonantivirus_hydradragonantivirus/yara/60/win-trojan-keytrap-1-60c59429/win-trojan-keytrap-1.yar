rule Win_Trojan_Keytrap_1
{
strings:
	$a0 = { b8ffffcd213d010074[4-9]b80935cd212e89 }


condition:
	$a0
}