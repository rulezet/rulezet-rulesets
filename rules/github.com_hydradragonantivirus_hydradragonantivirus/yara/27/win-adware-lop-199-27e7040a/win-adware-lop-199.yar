rule Win_Adware_Lop_199
{
strings:
	$a0 = { 4a820fdfb9cd608feea7e3d24ad85f79ca78ef2fd111fedecf7e7f6fa03e6ad98afe6a47aac9b8f887f4fa33f72ff86e483ef149cd5fc3ca173ecb02 }


condition:
	$a0
}