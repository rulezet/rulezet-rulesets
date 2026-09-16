rule Win_Trojan_Slava_1
{
strings:
	$a0 = { 8cd80502008ed8a1e2022ea30001a0e4022ea20201b8ffffcd213d1616745f06b82135cd21891ebc018c06be011e8c }


condition:
	$a0
}