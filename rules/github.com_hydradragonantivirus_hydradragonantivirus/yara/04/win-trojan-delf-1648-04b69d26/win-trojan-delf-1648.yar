rule Win_Trojan_Delf_1648
{
strings:
	$a0 = { 556818e6450064ff30648920b838e64500e8f25affffb850e64500e8e85affffb864e64500e8de5affffb87ce64500e8d45affffb894e64500e8ca5affff33c05a5959648910eb11 }


condition:
	$a0
}