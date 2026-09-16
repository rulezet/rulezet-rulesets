rule Win_Trojan_Bombole_3
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21ebaf80fcef741480fc4b741280fc3d74 }


condition:
	$a0
}