rule Win_Spyware_Banker_1470
{
strings:
	$a0 = { 1567ab5ee9f230b3e284c986ac6b58d711e29462deae173edf21438dc236352c1f7a2d6bddaa3a915e836571da91d080c67bd2aacacfd616583301ce424e4f0b8f2af50a }


condition:
	$a0
}