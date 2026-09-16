rule Win_Trojan_Trivial_276
{
strings:
	$a0 = { 2701b44ecd21721dba9e00b8023dcd21720f93ba0001b92d00b440cd21cc3ecd21b44febdfc3 }


condition:
	$a0
}