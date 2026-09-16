import "pe"
rule RansomImportDetect
{
	meta:
		Description  = "Ransom.Gen.ab"
		ThreatLevel  = "3"
	condition:
		(pe.imports("Kernel32.dll", "FindFirstFileW") or pe.imports("Kernel32.dll", "FindFirstFileA")) and
		(pe.imports("Kernel32.dll", "FindNextFileW") or pe.imports("Kernel32.dll", "FindNextFileA")) and
		(pe.imports("Advapi32.dll", "CryptAcquireContextW") or pe.imports("Advapi32.dll", "CryptAcquireContextA")) and
		pe.imports("Advapi32.dll", "CryptEncrypt") and
		pe.imports("Advapi32.dll", "CryptGenRandom")
}