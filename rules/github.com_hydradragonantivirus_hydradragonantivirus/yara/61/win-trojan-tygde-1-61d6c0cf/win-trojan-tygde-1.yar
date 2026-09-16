rule Win_Trojan_Tygde_1
{
strings:
	$a0 = { 33c05036a103003d4e497416be2300bf4a052e8a044636320600002e8844ff4f75f0bf7070ca263a8f8f7206cc8bdf }


condition:
	$a0
}