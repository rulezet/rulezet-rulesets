rule Win_Trojan_NightKnight_1
{
strings:
	$a0 = { 08008cdb83c3102e019c4003eb13fc0ebf00015781ee08015681c69607a5a5a55efc1e0633ff8edfb82135cd21891e }


condition:
	$a0
}