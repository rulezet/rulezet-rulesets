rule Win_Trojan_Mozilla_1
{
strings:
	$a0 = { 494578706c6f7265720061220d0a53746100000000ffcc31000642feda9d06bad111812c746c }


condition:
	$a0
}