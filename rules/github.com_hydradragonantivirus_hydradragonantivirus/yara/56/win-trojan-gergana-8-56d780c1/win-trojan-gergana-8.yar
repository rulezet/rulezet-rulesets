rule Win_Trojan_Gergana_8
{
strings:
	$a0 = { 0150ba80ffb41acd21ba2902b82425cd21b93f00ba8701b44ecd217303e9b200ba9effb80043cd217235890e2302b80143b92000cd217227ba9effb8023d }


condition:
	$a0
}