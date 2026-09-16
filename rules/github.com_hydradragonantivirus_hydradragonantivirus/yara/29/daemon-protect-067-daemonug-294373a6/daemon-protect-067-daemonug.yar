import "pe"
rule _DAEMON_Protect_067__DAEMONUG_
{
	meta:
		description = "DAEMON Protect 0.6.7 -> DAEMON/UG"
	strings:
		$0 = {60 60 9C 8C C9 32 C9 E3 0C}
	condition:
		$0 at pe.entry_point
}