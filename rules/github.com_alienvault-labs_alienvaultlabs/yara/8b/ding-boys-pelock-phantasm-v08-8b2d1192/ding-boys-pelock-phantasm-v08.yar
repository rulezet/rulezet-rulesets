rule _Ding_Boys_PElock_Phantasm_v08_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm v0.8"
	strings:
		$0 = {55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB}
	condition:
		$0 at entrypoint
}