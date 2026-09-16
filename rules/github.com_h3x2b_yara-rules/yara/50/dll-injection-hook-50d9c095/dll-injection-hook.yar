import "pe"
rule dll_injection_hook : suspicious feature dll injection windows
{
meta:
	description = "Injection using User32.dll:VirtualAllocEx"


condition:
	        uint16be(0) == 0x4d5a and

	(
		pe.imports("user32.dll","SetWindowsHookExA") or
		pe.imports("user32.dll","SetWindowsHookExW")
	)
}