rule Win_Trojan_Small_3399
{
strings:
	$a0 = { 6bc4587e8c7df50d654e6fc3b0eceea0eb2b9ece100a8064724fff420fe1312acdffce28507e93c3402b4e41ea59cdf24db96838f0ec856101ff0a777b89e06b625ebcaf915b042a656e0b49f217c5a1 }


condition:
	$a0
}