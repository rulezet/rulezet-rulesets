rule Win_Spyware_Banker_5871
{
strings:
	$a0 = { dbe3d92eab0d1776c1c9559be22f08250358138f5a2ae33ad7981bae024900105198c621ccee3fef6217bf67ac116414b539f0aca9018e03aaae9723009d5bbb7e1ab4fc }


condition:
	$a0
}