import "pe"
rule _MetaWare_High_C_RunTime_Library_p_Phar_Lap_DOS_Extender_198389_
{
	meta:
		description = "MetaWare High C Run-Time Library + Phar Lap DOS Extender 1983-89"
	strings:
		$0 = {B8 ?? ?? 50 B8 ?? ?? 50 CB}
	condition:
		$0 at pe.entry_point
}