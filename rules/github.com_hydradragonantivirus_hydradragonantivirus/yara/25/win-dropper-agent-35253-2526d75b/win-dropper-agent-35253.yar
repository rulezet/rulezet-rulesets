rule Win_Dropper_Agent_35253
{
strings:
	$a0 = { 5668f962ded00f58d809c8fe686b5a1d4ed8e7a1e44fbe668dc7b6df41fae423c38241c6b3a0fac1dcf4d7c5ad6c1a85d981b01fdebf23a18169fe6ec9f150da71779d6a9a473c8d2564786e7fd81000 }


condition:
	$a0
}