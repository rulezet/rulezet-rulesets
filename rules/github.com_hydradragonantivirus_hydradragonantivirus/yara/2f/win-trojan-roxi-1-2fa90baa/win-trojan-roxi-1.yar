rule Win_Trojan_Roxi_1
{
strings:
	$a0 = { f9e97303eb5f90b430cd4a6c696a796c6e735f697a5f576675675550213c026d0bba }


condition:
	$a0
}