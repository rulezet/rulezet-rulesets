rule Win_Trojan__0186_0006_001_1
{
strings:
	$a0 = { 33c933d2cd21b4408bd581c21501b90400cd21eb9d538bdd81c32501b93200902e8a0734ad2e88 }


condition:
	$a0
}