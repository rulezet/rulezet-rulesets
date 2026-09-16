rule Win_Trojan_Agent_31289
{
strings:
	$a0 = { 646f777300d0e0e7f0e5f8e8f2fc20fdf2eeecf320eff0e8ebeee6e5ede8fe20e2fbefeeebedfff2fc20ebfee1fbe520e4e5e9f1f2e2e8ff00416e566972205461736b204d61 }

	$a1 = { 6f777300d0e0e7f0e5f8e8f2fc20fdf2eeecf320eff0e8ebeee6e5ede8fe20e2fbefeeebedfff2fc20ebfee1fbe520e4e5e9f1f2e2e8ff00416e56697220546173 }


condition:
	$a0 and $a1
}