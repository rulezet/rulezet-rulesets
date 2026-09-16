rule Win_Spyware_Delf_16
{
strings:
	$a0 = { 37596227f8e7d08860003cb7f0ccba08a04c68ca7108d663a5b0aa2dacfdc4ba1ca06bff40886241214fac0314301e67f86f0205df494c2046524f4dc78d41a1 }


condition:
	$a0
}