rule Win_Trojan_Agent_35667
{
strings:
	$a0 = { 2f64[0-16]706870 }

	$a1 = { 69627574652822737263222c646c696e6b29 }

	$a2 = { 6520696e7465726e6574207669727573 }


condition:
	$a0 and $a1 and $a2
}