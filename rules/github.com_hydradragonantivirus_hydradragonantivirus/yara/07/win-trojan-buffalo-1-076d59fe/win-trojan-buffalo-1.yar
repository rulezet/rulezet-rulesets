rule Win_Trojan_Buffalo_1
{
strings:
	$a0 = { b801435048cc5872??f6c11c75??5051b120cc72??1e52b8023dcc8bd8e8????b43ecc }


condition:
	$a0
}