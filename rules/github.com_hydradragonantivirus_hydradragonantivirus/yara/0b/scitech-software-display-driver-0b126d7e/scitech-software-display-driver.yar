import "pe"
rule _Scitech_Software_Display_Driver_
{
	meta:
		description = "Scitech Software Display Driver"
	strings:
		$0 = {56 42 45 41 46 2E 44 52 56}
	condition:
		$0 at pe.entry_point
}