rule Win_Trojan_Minimal_7
{
strings:
	$a0 = { 01b44ecd21721dba9e00b8023dcd21720f93ba0001b92d00b440cd21b43ecd21b44febdfc32a2e636f6d00 }


condition:
	$a0
}