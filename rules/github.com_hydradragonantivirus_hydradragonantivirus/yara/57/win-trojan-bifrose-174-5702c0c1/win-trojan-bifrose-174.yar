rule Win_Trojan_Bifrose_174
{
strings:
	$a0 = { 5e90880050840b5121c5fdba009c89ed8a5ffaa99875b3188bc4de1017bc056f4969cb7b00eabb678c5c1f000a55bdfa3ffc97d707c169c330c267ece7902058f2b30200 }


condition:
	$a0
}