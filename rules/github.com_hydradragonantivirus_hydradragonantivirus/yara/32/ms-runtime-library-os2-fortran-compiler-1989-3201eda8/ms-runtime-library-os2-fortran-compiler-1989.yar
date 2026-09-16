import "pe"
rule _MS_RunTime_Library_OS2__FORTRAN_Compiler_1989_
{
	meta:
		description = "MS Run-Time Library (OS/2) & FORTRAN Compiler 1989"
	strings:
		$0 = {B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73}
	condition:
		$0 at pe.entry_point
}