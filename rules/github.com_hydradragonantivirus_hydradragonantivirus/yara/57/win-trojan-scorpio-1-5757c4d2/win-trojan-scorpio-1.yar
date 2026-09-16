rule Win_Trojan_Scorpio_1
{
strings:
	$a0 = { 0e57ff363a01bf40011e579a9700cc01833e080200740a31c09a16015402e99500bf5e011e }


condition:
	$a0
}