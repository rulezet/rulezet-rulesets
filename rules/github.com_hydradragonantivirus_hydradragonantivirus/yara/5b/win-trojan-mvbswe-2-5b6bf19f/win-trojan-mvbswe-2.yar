rule Win_Trojan_mvbswe_2
{
strings:
	$a0 = { 6d7662737765 }

	$a1 = { 2e676574657874656e73696f6e6e616d652866696c652e70617468293d2276627322 }


condition:
	$a0 and $a1
}