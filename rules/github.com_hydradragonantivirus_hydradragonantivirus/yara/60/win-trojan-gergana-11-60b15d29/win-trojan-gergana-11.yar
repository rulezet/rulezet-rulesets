rule Win_Trojan_Gergana_11
{
strings:
	$a0 = { 0150ba80ffb41acd21babf02b82425cd21b93f00ba8b01b44ecd217303e9b600ba9effb80043cd217235890e2e02b80143b92000cd217227ba9effb8023d }


condition:
	$a0
}