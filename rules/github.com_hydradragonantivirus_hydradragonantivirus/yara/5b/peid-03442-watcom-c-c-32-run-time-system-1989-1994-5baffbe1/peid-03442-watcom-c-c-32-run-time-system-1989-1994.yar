rule PEiD_03442_WATCOM_C_C___32_Run_Time_System_1989__1994_ {
  meta:
    description = "[WATCOM C/C++ 32 Run-Time System 1989, 1994]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }

  condition:
    $a
}