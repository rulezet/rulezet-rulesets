rule Win_Trojan_Dirtydog_1
{
strings:
	$a0 = { cd1306b8810150cbbe4c008b042ea304018b44022ea30601b83501cd133d360174302ec606 }


condition:
	$a0
}