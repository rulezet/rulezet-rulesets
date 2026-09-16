rule Win_Trojan_DSU_1
{
strings:
	$a0 = { 5b83eb038db7170056b94e052e80344646e2f9c3 }


condition:
	$a0
}