rule Win_Trojan_Tiny_106
{
strings:
	$a0 = { b82135cd21891e????8c06????b080cd216a200723db75??be000133ffb9d200f3a4061fb82125ba????cd21 }


condition:
	$a0
}