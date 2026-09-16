rule Win_Trojan_BAS36504_1
{
strings:
	$a0 = { 1f8bd3f2c1b440cd21b817ffba3800b93641f41fc606040000ff1beb1c901fcd112402d0e8 }


condition:
	$a0
}