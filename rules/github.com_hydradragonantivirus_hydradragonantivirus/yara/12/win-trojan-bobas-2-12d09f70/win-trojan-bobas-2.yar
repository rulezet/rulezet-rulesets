rule Win_Trojan_Bobas_2
{
strings:
	$a0 = { 25bab7019cff1e3300b440b92e0333d29cff1e3300b802428bca9cff1e33008af28ad4d1eaa9 }


condition:
	$a0
}