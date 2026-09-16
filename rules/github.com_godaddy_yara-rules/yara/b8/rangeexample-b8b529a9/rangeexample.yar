rule RangeExample {
	strings:
		$pe = "PE"
	
	condition:
		$pe in (32..100)
}