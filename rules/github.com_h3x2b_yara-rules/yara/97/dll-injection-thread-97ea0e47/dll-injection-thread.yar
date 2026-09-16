import "pe"
rule dll_injection_thread : suspicious feature dll injection windows
{
meta:
	description = "Injection using kernel32.dll:VirtualAllocEx"
	link = "http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html"

strings:
	$load_01 = "LoadLibraryA"

	$remote_01 = "NtCreateThreadEx"

condition:
	        uint16be(0) == 0x4d5a and

				
		(
		pe.imports("kernel32.dll","VirtualAllocEx")
	)and

		(
		pe.imports("kernel32.dll","WriteProcessMemory") or
		pe.imports("kernel32.dll","LoadLibraryExA") or
		pe.imports("kernel32.dll","LoadLibraryExW") or
		(
			pe.imports("kernel32.dll","GetProcAddress") and
			( pe.imports("kernel32.dll","GetModuleHandleA") or pe.imports("kernel32.dll","GetModuleHandleA") ) and
			$load_01
		)
	) and

		(
		pe.imports("kernel32.dll","CreateRemoteThread") or
		pe.imports("ntdll.dll","NtCreateThreadEx") or
		(
			pe.imports("kernel32.dll","GetProcAddress") and
			( pe.imports("kernel32.dll","GetModuleHandleA") or pe.imports("kernel32.dll","GetModuleHandleA") ) and
			$remote_01
		)
	)

}