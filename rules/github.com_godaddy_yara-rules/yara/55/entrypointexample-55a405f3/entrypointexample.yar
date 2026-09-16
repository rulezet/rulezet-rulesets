rule EntryPointExample {
	strings:
		$ep = { 55 8b ec }

	condition:
		$ep at entrypoint
}