rule Win_Trojan_SillyRC_11
{
strings:
	$a0 = { b82135cd2181fb5001742e891e5b018c065d010e58488ed8a103002c40a3030003c28ec0bf00010e1ffcb9c400f3a4 }


condition:
	$a0
}