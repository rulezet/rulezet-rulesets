rule Win_Trojan_Small_4518
{
strings:
	$a0 = { be21????018db6df555afee83e00000056e81100000051e8 }


condition:
	$a0
}