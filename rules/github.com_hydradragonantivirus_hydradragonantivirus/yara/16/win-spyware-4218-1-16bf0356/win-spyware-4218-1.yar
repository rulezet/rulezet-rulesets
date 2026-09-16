rule Win_Spyware_4218_1
{
strings:
	$a0 = { 5381c4f4fcffff33c08944241c33c0894424205468645f4000e822e8ffff }


condition:
	$a0
}