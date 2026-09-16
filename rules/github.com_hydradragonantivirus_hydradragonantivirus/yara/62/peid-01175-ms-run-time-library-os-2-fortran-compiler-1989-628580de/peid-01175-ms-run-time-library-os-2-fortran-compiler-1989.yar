rule PEiD_01175_MS_Run_Time_Library__OS_2____FORTRAN_Compiler_1989_ {
  meta:
    description = "[MS Run-Time Library (OS/2) & FORTRAN Compiler 1989]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }

  condition:
    $a
}