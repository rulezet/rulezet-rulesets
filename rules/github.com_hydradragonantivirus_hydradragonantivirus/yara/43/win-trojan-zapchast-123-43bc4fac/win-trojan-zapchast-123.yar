rule Win_Trojan_Zapchast_123
{
strings:
	$a0 = { 6e33303d20207768696c652028256331203c3d20256329 }

	$a1 = { 24676574746f6b[0-11]6b2824312d2c3332292c }


condition:
	$a0 and $a1
}