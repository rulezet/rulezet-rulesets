rule pe_base64d_pe : hardened
{
	meta:
		description = "Detects base64 encoded PE files"
		score = 50

	strings:
		$mz_header = {54 56 71 51}
		$this_program = {56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74}
		$null_bytes = {41 41 41 41 41}

	condition:
		$mz_header and $this_program and #null_bytes > 2
}