rule Win_Spyware_78857_1
{
strings:
	$a0 = { 42554d424c450000616e67656c }

	$a1 = { 6f6e5c52756e[0-19]7368617265206324202f64 }


condition:
	$a0 and $a1
}