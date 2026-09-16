rule OffsetExample {
	strings:
		$mz = "MZ"

	condition:
		$mz at 0
}