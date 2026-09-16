rule Win_Trojan_Samael_1
{
strings:
	$a0 = { 66656374696e672e2e2e5589e581ec5c0b8cd38ec38cdbfc8d7eb0c57608ac3c4f7202b04faa }


condition:
	$a0
}