rule _PE_Diminisher_v01_
{
	meta:
		description = "PE Diminisher v0.1"
	strings:
		$0 = {5D 8B D5 81 ED A2 30 40 2B 95 91 33 40 81 EA 0B 89 95 9A 33 40 80 BD}
		$1 = {60 9C BE ?? 10 40 ?? 8B FE B9 28 03 ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D}
	condition:
		$0 at entrypoint or $1 at entrypoint
}