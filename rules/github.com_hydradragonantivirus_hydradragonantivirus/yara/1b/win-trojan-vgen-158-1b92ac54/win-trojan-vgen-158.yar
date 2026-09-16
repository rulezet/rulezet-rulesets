rule Win_Trojan_VGEN_158
{
strings:
	$a0 = { 42cd21eb064459ec03d008b9d103be1b018bfeac3400aae2fab82135cd21891e66028c0668028cc8488ed8ac803e }


condition:
	$a0
}