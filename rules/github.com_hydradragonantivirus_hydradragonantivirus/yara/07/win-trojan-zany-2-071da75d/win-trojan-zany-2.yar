rule Win_Trojan_Zany_2
{
strings:
	$a0 = { d80500108ec0be00018bfeb18bf3a48ed81eb8180150cb29d2b41acd21ba5401b44eb53fcd21724bb8023dba1e00cd }


condition:
	$a0
}