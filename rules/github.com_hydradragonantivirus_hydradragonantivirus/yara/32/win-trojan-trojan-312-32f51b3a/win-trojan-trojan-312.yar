rule Win_Trojan_Trojan_312
{
strings:
	$a0 = { 3e9600017503e89828e83632ff361258ff361058e85d5f83c4046a196a506a016a01e8085e83c4 }


condition:
	$a0
}