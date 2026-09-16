rule Win_Spyware_Banker_3075
{
strings:
	$a0 = { 76869d96447ee33ca997a9efa7c41f3e8cdbdfae55d17745507fb38c810f07bf3a94f11b5d83009124b030ef6ce3da66880ec14104ce299311ca1ec55afc }


condition:
	$a0
}