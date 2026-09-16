rule Win_Trojan_Perry_1
{
strings:
	$a0 = { 8ed88c0629088ec0bad005e8c9ffe85000803e5908017625e88800e8d3ffe8d800720ae845017205e8d70073f6ba }


condition:
	$a0
}