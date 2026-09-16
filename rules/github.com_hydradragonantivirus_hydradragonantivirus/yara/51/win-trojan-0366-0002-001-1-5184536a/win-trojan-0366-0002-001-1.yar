rule Win_Trojan__0366_0002_001_1
{
strings:
	$a0 = { b4405a59cd21e83500b440b9b202ba0001cd21b801572e8b1698002e8b0e9600cd21b43ecd21b8 }


condition:
	$a0
}