rule Win_Trojan_Vgen_156
{
strings:
	$a0 = { 90e8020003c25d81ed03018db6b101bf0001a5a5b80033cd215232d2b80133cd21b82435cd215306baae0103d5 }


condition:
	$a0
}