rule Win_Spyware_Banker_2436
{
strings:
	$a0 = { f984728c6aee8207d877a383cfa2acbb681be64b9f0b8f5a8daa42fc4de611d7edc2fefeb0040e413587edb57e9e549c443a0d99dd6425006082d1acbf805c11fd73e71f45feb336fb28 }


condition:
	$a0
}