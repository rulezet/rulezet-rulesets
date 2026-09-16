rule Win_Trojan_Vienna_103
{
strings:
	$a0 = { 02890db440b93c03908bd681ea5402cd21721f3d3c03751ab80042b90000ba0000cd21720d }


condition:
	$a0
}