rule Win_Trojan_Coconut_2
{
strings:
	$a0 = { b8004c80ec22cd215d5281ed0801e808075a80fe0c750d80fa19740580fa1f7503e88701e8f400e81601e81e01 }


condition:
	$a0
}