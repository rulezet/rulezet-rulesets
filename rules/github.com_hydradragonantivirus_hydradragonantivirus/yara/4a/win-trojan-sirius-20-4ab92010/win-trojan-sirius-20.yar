rule Win_Trojan_Sirius_20
{
strings:
	$a0 = { 833e2e310c81c1aee083c6024821c07403f9ebee28fa82f36d5533b38dff3d9e975d2e3774a6f2e81fcd5a77dd1b54494f2900bc4b1d428a18b5b757 }


condition:
	$a0
}