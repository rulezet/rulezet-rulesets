rule RelativeOffsetExample {
	strings:
		$mz = "MZ"
		$pe = "PE"

	condition:
		$mz at 0 and $pe in (@mz[0]..0x200)
}