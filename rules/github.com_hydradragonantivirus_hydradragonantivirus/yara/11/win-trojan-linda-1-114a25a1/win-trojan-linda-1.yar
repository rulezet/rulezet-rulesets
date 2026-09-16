rule Win_Trojan_Linda_1
{
strings:
	$a0 = { 014d740b803e7f015a7404c646ff01833ebe39007506807eff01758a807eff007403e98200 }


condition:
	$a0
}