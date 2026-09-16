rule Win_Trojan_Bvone_1
{
strings:
	$a0 = { fe4d0572c8b91300be7b03bf980bf3a45bb8004299cd21b440595acd21b43ecd21eb8cf6069500 }


condition:
	$a0
}