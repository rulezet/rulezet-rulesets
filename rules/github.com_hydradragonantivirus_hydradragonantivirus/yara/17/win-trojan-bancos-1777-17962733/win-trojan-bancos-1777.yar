rule Win_Trojan_Bancos_1777
{
strings:
	$a0 = { af32cf455d31c342d168512da19e12a0cff93af97a7ec9a924e14adf1d37b9e155201042a107afdd3ae98d3f4989ffc17979b4fe81c8aa7f5ee84aef734a379286be5e41dfba }


condition:
	$a0
}