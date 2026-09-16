rule Win_Trojan_Elkern_2
{
strings:
	$a0 = { 9c60e8000000005d8d(b5|bd)(32|2d)(01|02)00008b5c242481e30000e0ff8d(b5|bd)(32|2d)(01|02)0000e8d60000008d(45|4d|55|5d)2b(50|51|52|53)8d(45|4d|55|5d)??(87|89)(ce|de|c6|d6)e8c8000000c381ed }


condition:
	$a0
}