rule Win_Spyware_10158_1
{
strings:
	$a0 = { 656e747365727665722e696e69 }

	$a1 = { 3f8d4000527e7f7f747265787e7f2b31527d7e62748d40003f3d3f233c3e3e23 }


condition:
	$a0 and $a1
}