rule Win_Trojan_Ceib_1
{
strings:
	$a0 = { f269f08f09f2c6063cfc01eb04fe18c6f9d9fed9bf82e1d1b09a4fe5c9fca0e730e46308c6 }


condition:
	$a0
}