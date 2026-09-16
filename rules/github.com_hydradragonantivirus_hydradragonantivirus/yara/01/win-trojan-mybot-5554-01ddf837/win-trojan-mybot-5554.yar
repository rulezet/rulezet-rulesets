rule Win_Trojan_Mybot_5554
{
strings:
	$a0 = { 411ec9475abf03bd7e54b207330bdcd3960292bcd9d1cf4b60e653554369cb663ed90efd9959aef76e47b76bdbb8b0d7c24b33be9d053e27f9189ff5ca57b7b90af9c7a111c1 }


condition:
	$a0
}