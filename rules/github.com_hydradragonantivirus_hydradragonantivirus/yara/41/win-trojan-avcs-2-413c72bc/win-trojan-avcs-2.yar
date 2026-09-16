rule Win_Trojan_AVCS_2
{
strings:
	$a0 = { cd2090909090e800005b81eb0e018beb8db62f01568b961702b971008bfe84c7fcad33c2ab3ae4e2f8 }


condition:
	$a0
}