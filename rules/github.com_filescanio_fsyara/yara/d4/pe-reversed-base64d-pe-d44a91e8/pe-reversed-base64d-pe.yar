rule pe_reversed_base64d_pe : hardened
{
	meta:
		description = "Detects reversed base64 encoded PE files"
		score = 50

	strings:
		$mz_header = {51 71 56 54}
		$this_program = {74 46 6d 63 6e 39 6d 63 77 42 79 63 70 68 47 56}
		$null_bytes = {41 41 41 41 41}

	condition:
		$mz_header and $this_program and #null_bytes > 2
}