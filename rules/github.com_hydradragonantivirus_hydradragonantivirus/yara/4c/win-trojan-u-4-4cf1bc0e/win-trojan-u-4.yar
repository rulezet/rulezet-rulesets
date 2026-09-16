rule Win_Trojan_U_4
{
strings:
	$a0 = { 4ad65613e54197a257b0a11b63e45a71 }

	$a1 = { 39d0c1432e13242b5ef5bbc70c1be68b }

	$a2 = { 358dd0043beb696c3ff559288e039b17 }


condition:
	$a0 and $a1 and $a2
}