rule Win_Trojan_Bancos_978
{
strings:
	$a0 = { c318bf6ff0c007f69e02e371093551a097b577bee7e7ba0c0aadad24e3b02610e3bca558168e940420be92e6a83fcf9a60a22e6f478f8cfafa22ec3d58e7cf2c23d028e78bbcaf66074e11c5145c }


condition:
	$a0
}