rule Win_Trojan_SubSeven_12
{
strings:
	$a0 = { a20dc504700a8c763c42de01193d0a890d65e6e9e5bac1043130c52569e7afd66d134ece2473363fd6ce38e143253fbecfa7ce77a7cdbd10079d0a1b01d0e465 }


condition:
	$a0
}